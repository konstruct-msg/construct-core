//! High-level transport API: Obfs4Stream and Obfs4Listener.
//!
//! These types wrap a TCP stream with the obfs4 handshake and framing,
//! presenting a standard `AsyncRead + AsyncWrite` interface to callers.
//! This means they're directly compatible with tonic and hyper.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use pin_project_lite::pin_project;
use rand::{SeedableRng, rngs::SmallRng};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    time::Sleep,
};

use crate::{
    Result,
    crypto::keypair::{NodeId, StaticKeypair},
    framing::{
        PaddingStrategy,
        decoder::{DecodedFrame, FrameDecoder},
        encoder::FrameEncoder,
    },
    handshake::{DEFAULT_HANDSHAKE_TIMEOUT, client::client_handshake, server::server_handshake},
    iat::{IatMode, sample_delay_with_max, split_for_iat},
    replay_filter::ReplayFilter,
};

/// Convert a 24-byte PRNG seed into the 32-byte seed required by SmallRng.
/// Uses the first 24 bytes and pads with a simple derivation.
fn prng_seed_to_rng_seed(seed: &[u8; 24]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..24].copy_from_slice(seed);
    // Derive remaining 8 bytes via XOR folding
    for i in 0..8 {
        out[24 + i] = seed[i] ^ seed[8 + i] ^ seed[16 + i];
    }
    out
}

// ── Client config ────────────────────────────────────────────────────────────

/// Configuration for the obfs4 client.
#[derive(Clone)]
pub struct ClientConfig {
    /// Server's static public key B (32 bytes, from bridge cert).
    pub server_pubkey: [u8; 32],
    /// Server's Node ID (20 bytes, from bridge cert).
    pub node_id: NodeId,
    /// IAT obfuscation mode (default: `None`).
    pub iat_mode: IatMode,
    /// Maximum time allowed for the handshake to complete.
    /// Prevents DPI probers from holding connections open indefinitely.
    pub handshake_timeout: Duration,
    /// Padding strategy for data frames.
    /// Random padding breaks correlation between payload and wire frame sizes.
    pub padding: PaddingStrategy,
    /// Maximum IAT delay per chunk.
    /// Default 10ms (Go-compatible). Set higher (e.g. 100-500ms) for stronger
    /// timing obfuscation that mimics real user think-time patterns.
    pub max_iat_delay: Duration,
}

impl ClientConfig {
    /// Create config from a base64-encoded bridge cert (`nodeID || pubKey`, no padding).
    /// Sets `iat_mode = IatMode::None`.
    pub fn from_bridge_cert(cert: &str) -> Result<Self> {
        let (server_pubkey, node_id) = StaticKeypair::parse_bridge_cert(cert)?;
        Ok(ClientConfig {
            server_pubkey,
            node_id,
            iat_mode: IatMode::None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        })
    }

    /// Parse config from a bridge line fragment: `cert=<cert> iat-mode=<n>`.
    ///
    /// The fragment may optionally contain other space-separated `key=value` pairs.
    /// Example: `"cert=AAECBAUGBwgJCgsMDQ4P... iat-mode=1"`
    pub fn from_bridge_line(line: &str) -> Result<Self> {
        let mut cert = None;
        let mut iat_mode = IatMode::None;
        for token in line.split_whitespace() {
            if let Some(v) = token.strip_prefix("cert=") {
                cert = Some(v);
            } else if let Some(v) = token.strip_prefix("iat-mode=") {
                iat_mode = v.parse()?;
            }
        }
        let cert = cert
            .ok_or_else(|| crate::Error::InvalidBridgeLine("missing cert in bridge line".into()))?;
        let (server_pubkey, node_id) = StaticKeypair::parse_bridge_cert(cert)?;
        Ok(ClientConfig {
            server_pubkey,
            node_id,
            iat_mode,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        })
    }

    /// Create config directly from raw bytes.
    pub fn new(server_pubkey: [u8; 32], node_id: NodeId) -> Self {
        ClientConfig {
            server_pubkey,
            node_id,
            iat_mode: IatMode::None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        }
    }

    /// Create config with explicit IAT mode.
    pub fn with_iat(mut self, iat_mode: IatMode) -> Self {
        self.iat_mode = iat_mode;
        self
    }

    /// Set the padding strategy for data frames.
    pub fn with_padding(mut self, padding: PaddingStrategy) -> Self {
        self.padding = padding;
        self
    }

    /// Set the maximum IAT delay per chunk.
    pub fn with_max_iat_delay(mut self, delay: Duration) -> Self {
        self.max_iat_delay = delay;
        self
    }
}

// ── Server config ────────────────────────────────────────────────────────────

/// Configuration for the obfs4 server.
pub struct ServerConfig {
    pub(crate) keypair: StaticKeypair,
    /// IAT obfuscation mode advertised in bridge lines (default: `None`).
    pub iat_mode: IatMode,
    /// Maximum time allowed for the handshake to complete.
    pub handshake_timeout: Duration,
    /// Padding strategy for data frames.
    pub padding: PaddingStrategy,
    /// Maximum IAT delay per chunk.
    pub max_iat_delay: Duration,
}

impl ServerConfig {
    /// Generate a new random server identity keypair with `IatMode::None`.
    pub fn generate() -> Self {
        ServerConfig {
            keypair: StaticKeypair::generate(&mut rand::rngs::OsRng),
            iat_mode: IatMode::None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        }
    }

    /// Create from an existing static keypair.
    pub fn from_keypair(keypair: StaticKeypair) -> Self {
        ServerConfig {
            keypair,
            iat_mode: IatMode::None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        }
    }

    /// Set the IAT mode.
    pub fn with_iat(mut self, iat_mode: IatMode) -> Self {
        self.iat_mode = iat_mode;
        self
    }

    /// Set the padding strategy for data frames.
    pub fn with_padding(mut self, padding: PaddingStrategy) -> Self {
        self.padding = padding;
        self
    }

    /// Set the maximum IAT delay per chunk.
    pub fn with_max_iat_delay(mut self, delay: Duration) -> Self {
        self.max_iat_delay = delay;
        self
    }

    /// Return the server's bridge cert (base64-encoded `nodeID || pubKey`, no padding).
    pub fn bridge_cert(&self) -> String {
        self.keypair.bridge_cert()
    }

    /// Return a bridge line fragment: `cert=<cert> iat-mode=<n>`.
    ///
    /// Clients pass this to [`ClientConfig::from_bridge_line`].
    pub fn bridge_line(&self) -> String {
        format!(
            "cert={} iat-mode={}",
            self.keypair.bridge_cert(),
            self.iat_mode.as_u8()
        )
    }

    /// Serialize the server identity to 52 raw bytes: `secret(32) || node_id(20)`.
    pub fn to_bytes(&self) -> [u8; 52] {
        let mut out = [0u8; 52];
        out[..32].copy_from_slice(&self.keypair.secret);
        out[32..].copy_from_slice(&self.keypair.node_id);
        out
    }

    /// Restore a server config from 52 bytes produced by [`ServerConfig::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != 52 {
            return Err(crate::Error::InvalidBridgeLine(format!(
                "server key must be 52 bytes, got {}",
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        let mut node_id = [0u8; 20];
        secret.copy_from_slice(&bytes[..32]);
        node_id.copy_from_slice(&bytes[32..]);
        Ok(ServerConfig {
            keypair: StaticKeypair::from_secret(secret, node_id),
            iat_mode: IatMode::None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            padding: PaddingStrategy::default(),
            max_iat_delay: crate::iat::MAX_IAT_DELAY,
        })
    }
}

pin_project! {
    /// An obfs4-wrapped stream implementing `AsyncRead + AsyncWrite`.
    ///
    /// The type parameter `S` is the underlying transport stream.
    /// Use [`Obfs4Stream<TcpStream>`] for plain TCP, or [`Obfs4Stream<TlsStream<TcpStream>>`]
    /// when wrapping obfs4 inside TLS for DPI evasion (TSPU/GFW).
    ///
    /// Obtained by calling [`Obfs4Stream::connect`] / [`Obfs4Stream::client_handshake`]
    /// (TCP), [`Obfs4Stream::client_handshake_stream`] (any stream),
    /// or from [`Obfs4Listener::accept`] / [`Obfs4Listener::accept_stream`].
    ///
    /// # IAT mode
    ///
    /// When `iat_mode` is `Enabled` or `Paranoid`, writes are split into chunks
    /// with random inter-chunk delays (0–10 ms) to resist traffic-timing analysis.
    /// The delays are applied during [`AsyncWrite::poll_flush`]; callers that
    /// always flush (e.g. tonic, hyper) get IAT behaviour automatically.
    pub struct Obfs4Stream<S> {
        #[pin]
        inner: S,
        encoder: FrameEncoder,
        decoder: FrameDecoder,
        read_buf: BytesMut,
        write_buf: BytesMut,
        iat_mode: IatMode,
        max_iat_delay: Duration,
        iat_chunks: VecDeque<Bytes>,
        iat_sleep: Option<Pin<Box<Sleep>>>,
        iat_rng: SmallRng,
    }
}

impl Obfs4Stream<TcpStream> {
    /// Connect to an obfs4 server: performs TCP connect + handshake.
    pub async fn connect(addr: &str, config: ClientConfig) -> Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        Self::client_handshake(tcp, config).await
    }

    /// Perform client handshake over an existing TCP stream.
    pub async fn client_handshake(tcp: TcpStream, config: ClientConfig) -> Result<Self> {
        Self::client_handshake_stream(tcp, config).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Obfs4Stream<S> {
    /// Perform client handshake over any async stream (TCP, TLS, or other).
    ///
    /// Use this when obfs4 runs inside another transport layer, e.g. TLS:
    /// ```rust,ignore
    /// let tls_stream = tls_connector.connect(domain, tcp).await?;
    /// let ice_stream = Obfs4Stream::client_handshake_stream(tls_stream, config).await?;
    /// ```
    pub async fn client_handshake_stream(stream: S, config: ClientConfig) -> Result<Self> {
        let iat_mode = config.iat_mode;
        let padding = config.padding;
        let max_iat_delay = config.max_iat_delay;
        let timeout = config.handshake_timeout;
        let (stream, result) = tokio::time::timeout(
            timeout,
            client_handshake(
                stream,
                &config.server_pubkey,
                &config.node_id,
                &mut rand::rngs::OsRng,
            ),
        )
        .await
        .map_err(|_| crate::Error::HandshakeTimeout)??;
        let keys = result.session_keys;

        let mut decoder = FrameDecoder::new(
            &keys.s2c_key,
            &keys.s2c_nonce_prefix,
            &keys.s2c_siphash_key,
            &keys.s2c_siphash_iv,
        );

        // Feed any trailing bytes from the handshake buffer into the decoder.
        // This handles inline frames (like PRNG seed) sent by the server
        // immediately after the handshake response.
        let mut iat_rng = SmallRng::from_entropy();
        if !result.trailing.is_empty() {
            decoder.feed(&result.trailing);
            loop {
                match decoder.decode_frame() {
                    Ok(Some(DecodedFrame::PrngSeed(seed))) => {
                        iat_rng = SmallRng::from_seed(prng_seed_to_rng_seed(&seed));
                    }
                    Ok(Some(DecodedFrame::Payload(_))) => {}
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }

        Ok(Obfs4Stream {
            inner: stream,
            encoder: FrameEncoder::new(
                &keys.c2s_key,
                &keys.c2s_nonce_prefix,
                &keys.c2s_siphash_key,
                &keys.c2s_siphash_iv,
            )
            .with_padding(padding),
            decoder,
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            iat_mode,
            max_iat_delay,
            iat_chunks: VecDeque::new(),
            iat_sleep: None,
            iat_rng,
        })
    }
    /// Send a cover-traffic heartbeat frame.
    ///
    /// Emits an empty payload frame (with padding if configured) that the
    /// receiver silently discards. Use this periodically on idle connections
    /// to mimic HTTP/2 PING frames and make traffic analysis harder.
    ///
    /// With `PaddingStrategy::PadToMax`, the heartbeat is indistinguishable
    /// from a max-sized data frame on the wire.
    pub async fn send_heartbeat(&mut self) -> std::io::Result<()>
    where
        Self: Unpin,
    {
        use tokio::io::AsyncWriteExt;
        // Encode a heartbeat directly bypassing the AsyncWrite impl
        // which skips empty payloads.
        let mut framed = BytesMut::new();
        let me = Pin::new(self).project();
        me.encoder
            .encode_heartbeat(&mut framed)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let inner = me.inner.get_mut();
        inner.write_all(&framed).await?;
        inner.flush().await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Obfs4Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut this = self.project();

        // Return buffered decoded data first
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }

        // Keep reading from TCP until we can decode at least one frame or EOF/error
        loop {
            let mut tmp = [0u8; 4096];
            let mut raw = ReadBuf::new(&mut tmp);
            match this.inner.as_mut().poll_read(cx, &mut raw) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = raw.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(())); // true EOF
                    }

                    this.decoder.feed(filled);

                    loop {
                        match this.decoder.decode_frame() {
                            Ok(Some(DecodedFrame::Payload(payload))) => {
                                this.read_buf.extend_from_slice(&payload);
                            }
                            Ok(Some(DecodedFrame::PrngSeed(seed))) => {
                                // Protocol polymorphism: reseed IAT RNG
                                *this.iat_rng = SmallRng::from_seed(prng_seed_to_rng_seed(&seed));
                                continue;
                            }
                            Ok(None) => break,
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    e.to_string(),
                                )));
                            }
                        }
                    }

                    if !this.read_buf.is_empty() {
                        let n = buf.remaining().min(this.read_buf.len());
                        buf.put_slice(&this.read_buf.split_to(n));
                        return Poll::Ready(Ok(()));
                    }
                    // No complete frame yet — loop to read more from TCP
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Obfs4Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();

        // Encode data into framed bytes
        let mut framed = BytesMut::new();
        if let Err(e) = this.encoder.encode(data, &mut framed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }

        if *this.iat_mode == IatMode::None {
            // ── IatMode::None: existing behaviour — buffer then flush immediately ──
            this.write_buf.extend_from_slice(&framed);
            while !this.write_buf.is_empty() {
                let pinned = this.inner.as_mut();
                match pinned.poll_write(cx, this.write_buf) {
                    Poll::Ready(Ok(n)) => {
                        let _ = this.write_buf.split_to(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => break,
                }
            }
        } else {
            // ── IatMode::Enabled / Paranoid: split into chunks, flush drives IAT ──
            let chunks = split_for_iat(&framed, *this.iat_mode, this.iat_rng);
            this.iat_chunks.extend(chunks);
        }

        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut this = self.project();

        if *this.iat_mode != IatMode::None {
            // ── Drain IAT chunks with inter-chunk delays ──────────────────────
            loop {
                // Wait for any in-progress inter-chunk sleep.
                if let Some(sleep) = this.iat_sleep {
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => *this.iat_sleep = None,
                    }
                }

                // Write the front chunk (if any).
                if this.iat_chunks.is_empty() {
                    break;
                }

                // Read chunk data without holding a mutable borrow during poll_write.
                let chunk_bytes: Bytes = this.iat_chunks.front().unwrap().clone();
                let pinned = this.inner.as_mut();
                match pinned.poll_write(cx, &chunk_bytes) {
                    Poll::Ready(Ok(n)) if n >= chunk_bytes.len() => {
                        this.iat_chunks.pop_front();
                        // Schedule delay before the next chunk.
                        if !this.iat_chunks.is_empty() {
                            let delay: Duration =
                                sample_delay_with_max(this.iat_rng, *this.max_iat_delay);
                            *this.iat_sleep = Some(Box::pin(tokio::time::sleep(delay)));
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        // Partial write: advance the front chunk.
                        *this.iat_chunks.front_mut().unwrap() = chunk_bytes.slice(n..);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        } else {
            // ── IatMode::None: flush write_buf ────────────────────────────────
            while !this.write_buf.is_empty() {
                let pinned = this.inner.as_mut();
                match pinned.poll_write(cx, this.write_buf) {
                    Poll::Ready(Ok(n)) => {
                        let _ = this.write_buf.split_to(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        this.inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ── Obfs4Listener ────────────────────────────────────────────────────────────

/// An obfs4 server listener. Wraps `TcpListener` with obfs4 handshake.
pub struct Obfs4Listener {
    inner: TcpListener,
    config: ServerConfig,
    replay_filter: Arc<Mutex<ReplayFilter>>,
}

impl Obfs4Listener {
    /// Bind to an address and start accepting obfs4 connections.
    pub async fn bind(addr: &str, config: ServerConfig) -> Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Obfs4Listener {
            inner,
            config,
            replay_filter: Arc::new(Mutex::new(ReplayFilter::new())),
        })
    }

    /// Create from an already-bound `TcpListener`.
    ///
    /// Useful when the caller needs to bind the socket itself (e.g. to set
    /// socket options or share the listener with other code).
    pub fn from_listener(listener: TcpListener, config: ServerConfig) -> Self {
        Obfs4Listener {
            inner: listener,
            config,
            replay_filter: Arc::new(Mutex::new(ReplayFilter::new())),
        }
    }

    /// Accept the next incoming TCP connection **without** the obfs4 handshake.
    ///
    /// Use this when you need to wrap the TCP stream in another layer (e.g. TLS)
    /// before calling [`accept_stream`](Self::accept_stream):
    /// ```rust,ignore
    /// let (tcp, addr) = listener.accept_tcp().await?;
    /// let tls = tls_acceptor.accept(tcp).await?;
    /// let ice = listener.accept_stream(tls).await?;
    /// ```
    pub async fn accept_tcp(&self) -> Result<(TcpStream, std::net::SocketAddr)> {
        Ok(self.inner.accept().await?)
    }

    /// Accept the next incoming obfs4 connection over TCP.
    ///
    /// Performs TCP accept + obfs4 server handshake. Replayed handshakes
    /// (active probing defence) are silently rejected with a random delay.
    pub async fn accept(&self) -> Result<(Obfs4Stream<TcpStream>, std::net::SocketAddr)> {
        let (tcp, addr) = self.inner.accept().await?;
        let stream = self.accept_stream(tcp).await?;
        Ok((stream, addr))
    }

    /// Perform obfs4 server handshake over an already-accepted stream.
    ///
    /// Use this when the connection arrives pre-wrapped in another transport,
    /// e.g. TLS terminated by the gateway before obfs4:
    /// ```rust,ignore
    /// let (tls_stream, _addr) = tls_acceptor.accept(tcp).await?;
    /// let ice_stream = listener.accept_stream(tls_stream).await?;
    /// ```
    pub async fn accept_stream<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<Obfs4Stream<S>> {
        let timeout = self.config.handshake_timeout;
        let (stream, result) = tokio::time::timeout(
            timeout,
            server_handshake(
                stream,
                &self.config.keypair,
                &mut rand::rngs::OsRng,
                &self.replay_filter,
            ),
        )
        .await
        .map_err(|_| crate::Error::HandshakeTimeout)??;
        let keys = result.session_keys;

        let mut ice_stream = Obfs4Stream {
            inner: stream,
            encoder: FrameEncoder::new(
                &keys.s2c_key,
                &keys.s2c_nonce_prefix,
                &keys.s2c_siphash_key,
                &keys.s2c_siphash_iv,
            )
            .with_padding(self.config.padding),
            decoder: FrameDecoder::new(
                &keys.c2s_key,
                &keys.c2s_nonce_prefix,
                &keys.c2s_siphash_key,
                &keys.c2s_siphash_iv,
            ),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            iat_mode: self.config.iat_mode,
            max_iat_delay: self.config.max_iat_delay,
            iat_chunks: VecDeque::new(),
            iat_sleep: None,
            iat_rng: SmallRng::from_entropy(),
        };

        // Protocol polymorphism: send a PRNG seed inline frame so each
        // connection gets a unique statistical profile.
        let mut seed = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        let mut seed_frame = BytesMut::new();
        ice_stream
            .encoder
            .encode_prng_seed(&seed, &mut seed_frame)?;
        {
            use std::pin::Pin;
            use tokio::io::AsyncWriteExt;
            Pin::new(&mut ice_stream.inner)
                .write_all(&seed_frame)
                .await?;
            Pin::new(&mut ice_stream.inner).flush().await?;
        }
        ice_stream.iat_rng = SmallRng::from_seed(prng_seed_to_rng_seed(&seed));

        Ok(ice_stream)
    }
}
