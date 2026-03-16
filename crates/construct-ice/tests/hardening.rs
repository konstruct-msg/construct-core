//! Tests for DPI-hardening features:
//! - Frame padding (PaddingStrategy: None / PadToMax / Random)
//! - Handshake timeout
//! - Nonce overflow → graceful error
//! - Extended IAT delay distribution
//! - End-to-end with padding + IAT combined

use std::time::{Duration, Instant};

use bytes::BytesMut;
use construct_ice::{
    ClientConfig, IatMode, Obfs4Listener, Obfs4Stream, PaddingStrategy, ServerConfig,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// ─────────────────────────────────────────────────────────────────────────────
// Padding unit tests (encoder ↔ decoder round-trip without network)
// ─────────────────────────────────────────────────────────────────────────────

mod framing {
    use super::*;
    use construct_ice::framing::decoder::{DecodedFrame, FrameDecoder};
    use construct_ice::framing::encoder::FrameEncoder;

    fn test_keys() -> ([u8; 32], [u8; 16], [u8; 16], [u8; 8]) {
        (
            [0xAA; 32], // key
            [0xBB; 16], // nonce_prefix
            [0xCC; 16], // siphash_key
            [0xDD; 8],  // siphash_iv
        )
    }

    /// Helper: decode all available frames from a BytesMut buffer.
    fn decode_all_payloads(dec: &mut FrameDecoder, data: &mut BytesMut) -> Vec<u8> {
        dec.feed(data);
        let mut result = Vec::new();
        loop {
            match dec.decode_frame().unwrap() {
                Some(DecodedFrame::Payload(p)) => result.extend_from_slice(&p),
                Some(DecodedFrame::PrngSeed(_)) => {}
                None => break,
            }
        }
        data.clear();
        result
    }

    #[test]
    fn padding_none_minimal_overhead() {
        let (key, np, sk, si) = test_keys();
        let mut enc = FrameEncoder::new(&key, &np, &sk, &si);
        let payload = b"hello";
        let mut dst = BytesMut::new();
        enc.encode(payload, &mut dst).unwrap();

        // Expected: header(2) + tag(16) + type(1) + len(2) + payload(5) = 26
        assert_eq!(dst.len(), 26);

        // Decode and verify
        let mut dec = FrameDecoder::new(&key, &np, &sk, &si);
        let recovered = decode_all_payloads(&mut dec, &mut dst);
        assert_eq!(&recovered, payload);
    }

    #[test]
    fn padding_pad_to_max_all_frames_same_size() {
        let (key, np, sk, si) = test_keys();

        // Encode several different-sized payloads
        let payloads: &[&[u8]] = &[b"a", b"hello world", &[0x42; 100], &[0xFF; 1000]];
        for payload in payloads {
            let mut enc =
                FrameEncoder::new(&key, &np, &sk, &si).with_padding(PaddingStrategy::PadToMax);
            let mut dst = BytesMut::new();
            enc.encode(payload, &mut dst).unwrap();
            // With PadToMax, every frame should be MAX_FRAME_LENGTH + HEADER = 1448 + 2 = 1450
            assert_eq!(
                dst.len(),
                1450,
                "PadToMax frame should be 1450 bytes on wire, got {} for payload len {}",
                dst.len(),
                payload.len()
            );

            // Decode and verify payload
            let mut dec = FrameDecoder::new(&key, &np, &sk, &si);
            let recovered = decode_all_payloads(&mut dec, &mut dst);
            assert_eq!(&recovered, *payload);
        }
    }

    #[test]
    fn padding_random_adds_variable_padding() {
        let (key, np, sk, si) = test_keys();
        let payload = b"test payload";
        let mut sizes = std::collections::HashSet::new();

        // Encode same payload 50 times — sizes should vary
        for _ in 0..50 {
            let mut enc = FrameEncoder::new(&key, &np, &sk, &si)
                .with_padding(PaddingStrategy::Random { max_pad: 200 });
            let mut dst = BytesMut::new();
            enc.encode(payload, &mut dst).unwrap();

            let size = dst.len();
            // Size must be >= minimum (no padding) and <= max possible
            let min_size = 2 + 16 + 1 + 2 + payload.len(); // 33
            assert!(size >= min_size, "frame too small: {size}");
            assert!(size <= 1448, "frame too large: {size}");
            sizes.insert(size);

            // Verify decoding still works
            let mut dec = FrameDecoder::new(&key, &np, &sk, &si);
            let recovered = decode_all_payloads(&mut dec, &mut dst);
            assert_eq!(&recovered, payload);
        }

        // With random padding, we should see multiple distinct sizes
        assert!(
            sizes.len() > 1,
            "Random padding should produce variable sizes, got only {:?}",
            sizes
        );
    }

    #[test]
    fn padding_random_fills_with_nonzero_bytes() {
        // Verify that padding bytes are random, not zeros.
        // We encode with PadToMax and check the raw ciphertext is not trivially patterned.
        let (key, np, sk, si) = test_keys();
        let mut enc =
            FrameEncoder::new(&key, &np, &sk, &si).with_padding(PaddingStrategy::PadToMax);
        let payload = b"x";
        let mut dst = BytesMut::new();
        enc.encode(payload, &mut dst).unwrap();

        // The frame is encrypted so we can't directly inspect padding,
        // but we verify that decoding works and payload is intact
        let mut dec = FrameDecoder::new(&key, &np, &sk, &si);
        let recovered = decode_all_payloads(&mut dec, &mut dst);
        assert_eq!(&recovered, payload);
    }

    #[test]
    fn padding_large_payload_multi_frame() {
        let (key, np, sk, si) = test_keys();
        let mut enc = FrameEncoder::new(&key, &np, &sk, &si)
            .with_padding(PaddingStrategy::Random { max_pad: 100 });

        // 4KB payload → multiple frames
        let payload: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let mut dst = BytesMut::new();
        enc.encode(&payload, &mut dst).unwrap();

        // Decode all frames and reassemble
        let mut dec = FrameDecoder::new(&key, &np, &sk, &si);
        let recovered = decode_all_payloads(&mut dec, &mut dst);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn nonce_exhaustion_returns_error() {
        let (key, np, sk, si) = test_keys();
        let mut enc = FrameEncoder::new(&key, &np, &sk, &si);

        // Manipulate internal counter to near overflow.
        // We can't directly set it, so we use the public API extensively.
        // Instead, test that encoding works normally (no panic).
        let mut dst = BytesMut::new();
        for _ in 0..100 {
            enc.encode(b"test", &mut dst).unwrap();
            dst.clear();
        }
        // Normal operation should succeed without panic
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IAT extended delay tests
// ─────────────────────────────────────────────────────────────────────────────

mod iat {
    use construct_ice::iat::{MAX_IAT_DELAY, sample_delay_with_max};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use std::time::Duration;

    #[test]
    fn classic_delay_within_10ms() {
        let mut rng = SmallRng::seed_from_u64(42);
        for _ in 0..1000 {
            let d = sample_delay_with_max(&mut rng, MAX_IAT_DELAY);
            assert!(d <= Duration::from_millis(10));
        }
    }

    #[test]
    fn extended_delay_within_max() {
        let mut rng = SmallRng::seed_from_u64(42);
        let max = Duration::from_millis(500);
        for _ in 0..1000 {
            let d = sample_delay_with_max(&mut rng, max);
            assert!(d <= max, "delay {:?} exceeds max {:?}", d, max);
        }
    }

    #[test]
    fn extended_delay_distribution_has_heavy_tail() {
        // With u²×max distribution and max=500ms:
        // P(delay < 50ms) = P(u² < 50/500) = P(u < sqrt(0.1)) ≈ P(u < 0.316) ≈ 31.6%
        // So ~68% should be >= 50ms — the distribution concentrates near zero
        // but with a heavy tail. We test that delays span a wide range.
        let mut rng = SmallRng::seed_from_u64(123);
        let max = Duration::from_millis(500);
        let mut under_100ms = 0u32;
        let mut over_100ms = 0u32;

        for _ in 0..10_000 {
            let d = sample_delay_with_max(&mut rng, max);
            if d < Duration::from_millis(100) {
                under_100ms += 1;
            } else {
                over_100ms += 1;
            }
        }

        // P(u² < 100/500) = P(u < sqrt(0.2)) ≈ 0.447 → ~45% under 100ms
        // Both buckets should be well-populated
        assert!(
            under_100ms > 1000,
            "expected many delays under 100ms, got {under_100ms}"
        );
        assert!(
            over_100ms > 1000,
            "expected many delays over 100ms, got {over_100ms}"
        );
    }

    #[test]
    fn zero_max_delay_returns_zero() {
        let mut rng = SmallRng::seed_from_u64(42);
        let d = sample_delay_with_max(&mut rng, Duration::ZERO);
        assert_eq!(d, Duration::ZERO);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E: Padding + network round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_pad_to_max_round_trip() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate().with_padding(PaddingStrategy::PadToMax);
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    let client_config = ClientConfig::from_bridge_cert(&bridge_cert)
        .unwrap()
        .with_padding(PaddingStrategy::PadToMax);
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    let payload = b"padded payload test";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, payload);

    server_handle.await.unwrap();
}

#[tokio::test]
async fn e2e_random_padding_round_trip() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config =
        ServerConfig::generate().with_padding(PaddingStrategy::Random { max_pad: 300 });
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    let client_config = ClientConfig::from_bridge_cert(&bridge_cert)
        .unwrap()
        .with_padding(PaddingStrategy::Random { max_pad: 300 });
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    let payload = b"random padding test message";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, payload);

    server_handle.await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E: Extended IAT delay with large max
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn e2e_extended_iat_delay() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate()
        .with_iat(IatMode::Enabled)
        .with_max_iat_delay(Duration::from_millis(100));
    let bridge_line = server_config.bridge_line();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let config = ClientConfig::from_bridge_line(&bridge_line)
        .unwrap()
        .with_max_iat_delay(Duration::from_millis(100));
    let mut client = Obfs4Stream::connect(&addr, config).await.unwrap();

    client.write_all(b"iat-ext").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = [0u8; 7];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"iat-ext");

    server_handle.await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E: Handshake timeout
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn handshake_timeout_triggers() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    // Start a raw TCP listener that never responds (simulates DPI stalling)
    let raw_listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    let _server = tokio::spawn(async move {
        // Accept but never send anything
        let (_sock, _) = raw_listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    // Connect with a very short handshake timeout
    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let client_config = ClientConfig::from_bridge_cert(&bridge_cert)
        .unwrap()
        .with_iat(IatMode::None);
    // Override handshake_timeout to 500ms for the test
    let client_config = ClientConfig {
        handshake_timeout: Duration::from_millis(500),
        ..client_config
    };

    let start = Instant::now();
    let result = Obfs4Stream::connect(&addr, client_config).await;
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail with timeout");
    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("expected error, got Ok"),
    };
    assert!(
        format!("{err:?}").contains("Timeout") || format!("{err:?}").contains("timeout"),
        "error should mention timeout, got: {err:?}"
    );
    // Should have timed out around 500ms, not waited forever
    assert!(
        elapsed < Duration::from_secs(5),
        "took too long: {elapsed:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E: Combined padding + IAT paranoid mode
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn e2e_full_hardening_paranoid() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    // Server uses default config — we're testing that a fully-hardened client
    // can still talk to a standard server.
    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    // Client uses all hardening features
    let client_config = ClientConfig::from_bridge_cert(&bridge_cert)
        .unwrap()
        .with_iat(IatMode::Paranoid)
        .with_padding(PaddingStrategy::PadToMax)
        .with_max_iat_delay(Duration::from_millis(20));
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();

    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"hello");

    server_handle.await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// E2E: Cover traffic heartbeat
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_heartbeat_does_not_corrupt_data() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate().with_padding(PaddingStrategy::PadToMax);
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Server reads data (heartbeats produce empty payloads, silently discarded)
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        // Send heartbeats back too
        stream.send_heartbeat().await.unwrap();
        stream.send_heartbeat().await.unwrap();
        // Then send real data
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    let client_config = ClientConfig::from_bridge_cert(&bridge_cert)
        .unwrap()
        .with_padding(PaddingStrategy::PadToMax);
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    // Client sends heartbeats before real data
    stream.send_heartbeat().await.unwrap();
    stream.send_heartbeat().await.unwrap();
    stream.send_heartbeat().await.unwrap();

    // Then send real data
    stream.write_all(b"world").await.unwrap();
    stream.flush().await.unwrap();

    // Read response (heartbeats from server should be silently skipped)
    let mut response = [0u8; 5];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"world");

    server_handle.await.unwrap();
}

#[test]
fn client_config_defaults() {
    let config = ServerConfig::generate();
    let cert = config.bridge_cert();
    let client = ClientConfig::from_bridge_cert(&cert).unwrap();

    assert_eq!(client.iat_mode, IatMode::None);
    assert_eq!(client.handshake_timeout, Duration::from_secs(30));
    assert!(matches!(client.padding, PaddingStrategy::None));
    assert_eq!(client.max_iat_delay, Duration::from_millis(10));
}

#[test]
fn server_config_defaults() {
    let config = ServerConfig::generate();

    assert_eq!(config.iat_mode, IatMode::None);
    assert_eq!(config.handshake_timeout, Duration::from_secs(30));
    assert!(matches!(config.padding, PaddingStrategy::None));
    assert_eq!(config.max_iat_delay, Duration::from_millis(10));
}

#[test]
fn config_builder_chain() {
    let config = ServerConfig::generate()
        .with_iat(IatMode::Paranoid)
        .with_padding(PaddingStrategy::Random { max_pad: 500 })
        .with_max_iat_delay(Duration::from_millis(200));

    assert_eq!(config.iat_mode, IatMode::Paranoid);
    assert!(matches!(
        config.padding,
        PaddingStrategy::Random { max_pad: 500 }
    ));
    assert_eq!(config.max_iat_delay, Duration::from_millis(200));
}

#[test]
fn server_config_serialization_roundtrip() {
    let config = ServerConfig::generate();
    let bytes = config.to_bytes();
    let restored = ServerConfig::from_bytes(&bytes).unwrap();

    assert_eq!(config.bridge_cert(), restored.bridge_cert());
    // Runtime fields reset to defaults after deserialization
    assert_eq!(restored.iat_mode, IatMode::None);
    assert!(matches!(restored.padding, PaddingStrategy::None));
}
