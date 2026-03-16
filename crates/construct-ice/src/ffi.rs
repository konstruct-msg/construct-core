//! C FFI — local TCP proxy for iOS integration.
//!
//! # Architecture
//!
//! ## Plain obfs4 mode (legacy)
//! ```text
//! [Swift gRPC] -> 127.0.0.1:PORT (plain TCP)
//!     -> [Rust proxy] -> Obfs4Stream -> relay:9443 (obfuscated)
//!     -> [relay VPS] -> main server
//! ```
//!
//! ## TLS-over-obfs4 mode (DPI evasion)
//! ```text
//! [Swift gRPC] -> 127.0.0.1:PORT (plain TCP)
//!     -> [Rust proxy] -> TLS(SNI=ice.domain) -> obfs4 handshake -> relay:443
//!     -> Traefik TCP passthrough -> gateway TLS termination
//!     -> obfs4 listener -> gRPC -> main server
//! ```
//!
//! # Usage (from Swift via bridging header)
//!
//! ```c
//! // Plain obfs4 (legacy)
//! int32_t ice_proxy_start(const char *bridge_line, const char *relay_addr, uint16_t *port_out);
//! // TLS-wrapped obfs4 for DPI evasion
//! int32_t ice_proxy_start_tls(const char *bridge_line, const char *relay_addr,
//!                             const char *tls_server_name, uint16_t *port_out);
//! int32_t ice_proxy_stop(void);
//! int32_t ice_proxy_is_running(void);
//! uint16_t ice_proxy_port(void);
//! ```

use std::{
    ffi::{CStr, c_char},
    sync::{Mutex, OnceLock},
};

use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::oneshot,
};

use crate::transport::{ClientConfig, Obfs4Stream};

fn get_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("ice: failed to create tokio runtime")
    })
}

struct ProxyHandle {
    port: u16,
    shutdown_tx: oneshot::Sender<()>,
}

static PROXY: Mutex<Option<ProxyHandle>> = Mutex::new(None);

#[unsafe(no_mangle)]
/// Start the obfs4 proxy.
///
/// `bridge_line` — bridge parameters string (e.g. `"cert=<base64> iat-mode=0"`).
/// `relay_addr`  — relay address in `"host:port"` format.
/// `port_out`    — output parameter: local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ice_proxy_start(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };

    let config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        // Check if already running without holding the lock across await
        {
            let guard = PROXY.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop(listener, relay_addr, config, shutdown_rx));
        let mut guard = PROXY.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[unsafe(no_mangle)]
/// Stop the running proxy. Returns 0 on success, -1 if not running.
pub extern "C" fn ice_proxy_stop() -> i32 {
    let mut guard = match PROXY.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    match guard.take() {
        Some(handle) => {
            let _ = handle.shutdown_tx.send(());
            0
        }
        None => -1,
    }
}

#[unsafe(no_mangle)]
/// Returns 1 if the proxy is currently running, 0 otherwise.
pub extern "C" fn ice_proxy_is_running() -> i32 {
    match PROXY.lock() {
        Ok(guard) => i32::from(guard.is_some()),
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
/// Returns the local TCP port the proxy is listening on, or 0 if not running.
pub extern "C" fn ice_proxy_port() -> u16 {
    match PROXY.lock() {
        Ok(guard) => guard.as_ref().map(|h| h.port).unwrap_or(0),
        Err(_) => 0,
    }
}

async fn proxy_loop(
    listener: TcpListener,
    relay_addr: String,
    config: ClientConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let addr = relay_addr.clone();
                        let cfg  = config.clone();
                        tokio::spawn(handle_connection(local, addr, cfg));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

async fn handle_connection(mut local: TcpStream, relay_addr: String, config: ClientConfig) {
    match Obfs4Stream::connect(&relay_addr, config).await {
        Ok(mut remote) => {
            let _ = copy_bidirectional(&mut local, &mut remote).await;
        }
        Err(e) => {
            eprintln!("ice: relay connect failed: {e}");
        }
    }
}

// ── TLS-wrapped proxy ─────────────────────────────────────────────────────────
//
// `ice_proxy_start_tls` starts a second proxy instance that establishes an
// outer TLS connection to the relay before the obfs4 handshake. This makes
// the traffic look like normal HTTPS to DPI systems.
//
// The `tls` Cargo feature must be enabled for these symbols to be compiled.

#[cfg(feature = "tls")]
static PROXY_TLS: Mutex<Option<ProxyHandle>> = Mutex::new(None);

#[cfg(feature = "tls")]
#[unsafe(no_mangle)]
/// Start the TLS-wrapped obfs4 proxy for DPI evasion.
///
/// Connections flow: local TCP → TLS to `relay_addr` (SNI=`tls_server_name`) → obfs4 → server.
///
/// `bridge_line`      — bridge parameters (e.g. `"cert=<base64> iat-mode=0"`).
/// `relay_addr`       — relay address: `"ice.example.com:443"`.
/// `tls_server_name`  — TLS SNI hostname: `"ice.example.com"`.
/// `port_out`         — local TCP port the proxy listens on.
///
/// Returns 0 on success, -1 on failure. Stop with [`ice_proxy_stop`].
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ice_proxy_start_tls(
    bridge_line: *const c_char,
    relay_addr: *const c_char,
    tls_server_name: *const c_char,
    port_out: *mut u16,
) -> i32 {
    let bridge_line = unsafe {
        match bridge_line
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let relay_addr = unsafe {
        match relay_addr
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };
    let tls_server_name = unsafe {
        match tls_server_name
            .as_ref()
            .and_then(|p| CStr::from_ptr(p).to_str().ok())
        {
            Some(s) => s.to_owned(),
            None => return -1,
        }
    };

    let config = match ClientConfig::from_bridge_line(&bridge_line) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let rt = get_runtime();
    let result: Result<u16, ()> = rt.block_on(async {
        {
            let guard = PROXY_TLS.lock().map_err(|_| ())?;
            if guard.is_some() {
                return Err(()); // already running
            }
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|_| ())?;
        let port = listener.local_addr().map_err(|_| ())?.port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        rt.spawn(proxy_loop_tls(
            listener,
            relay_addr,
            tls_server_name,
            config,
            shutdown_rx,
        ));
        let mut guard = PROXY_TLS.lock().map_err(|_| ())?;
        *guard = Some(ProxyHandle { port, shutdown_tx });
        Ok(port)
    });

    match result {
        Ok(p) => {
            if !port_out.is_null() {
                unsafe { *port_out = p };
            }
            0
        }
        Err(()) => -1,
    }
}

#[cfg(feature = "tls")]
async fn proxy_loop_tls(
    listener: TcpListener,
    relay_addr: String,
    tls_server_name: String,
    config: ClientConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => break,
            result = listener.accept() => {
                match result {
                    Ok((local, _)) => {
                        let addr = relay_addr.clone();
                        let sni  = tls_server_name.clone();
                        let cfg  = config.clone();
                        tokio::spawn(handle_connection_tls(local, addr, sni, cfg));
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(feature = "tls")]
async fn handle_connection_tls(
    mut local: TcpStream,
    relay_addr: String,
    tls_server_name: String,
    config: ClientConfig,
) {
    use native_tls::TlsConnector as NativeTlsConnector;
    use tokio::net::TcpStream as TokioTcp;
    use tokio_native_tls::TlsConnector;

    // 1. TCP connect to relay
    let tcp = match TokioTcp::connect(&relay_addr).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ice-tls: tcp connect failed: {e}");
            return;
        }
    };

    // 2. TLS handshake — uses platform native TLS (SecureTransport on iOS/macOS).
    //    Certificate is verified against the system CA store (Let's Encrypt).
    //    No custom ALPN or certificate pinning required per spec.
    let native_connector = match NativeTlsConnector::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ice-tls: TLS connector build failed: {e}");
            return;
        }
    };
    let connector = TlsConnector::from(native_connector);
    let tls_stream = match connector.connect(&tls_server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ice-tls: TLS handshake failed: {e}");
            return;
        }
    };

    // 3. obfs4 handshake over the TLS stream, then bidirectional proxy
    match Obfs4Stream::client_handshake_stream(tls_stream, config).await {
        Ok(mut remote) => {
            let _ = copy_bidirectional(&mut local, &mut remote).await;
        }
        Err(e) => {
            eprintln!("ice-tls: obfs4 handshake failed: {e}");
        }
    }
}
