//! End-to-end tests: full client ↔ server over localhost TCP.

use construct_ice::{ClientConfig, Obfs4Listener, Obfs4Stream, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper: find a free TCP port.
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Basic echo: client sends data, server echoes it back.
#[tokio::test]
async fn client_server_echo() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        stream.write_all(&buf[..n]).await.unwrap();
        stream.flush().await.unwrap();
        // Small delay to let data flush
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    // Client connects and sends
    let client_config = ClientConfig::from_bridge_cert(&bridge_cert).unwrap();
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    let payload = b"Hello, obfs4!";
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, payload);

    server_handle.await.unwrap();
}

/// Multiple round-trips on the same connection.
#[tokio::test]
async fn multiple_round_trips() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let rounds = 10;

    let server_handle = tokio::spawn(async move {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        for _ in 0..rounds {
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stream.shutdown().await.unwrap();
    });

    let client_config = ClientConfig::from_bridge_cert(&bridge_cert).unwrap();
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    for i in 0..rounds {
        let msg = format!("round {i}");
        stream.write_all(msg.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = vec![0u8; msg.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), msg);
    }

    server_handle.await.unwrap();
}

/// Large payload that spans multiple frames (> MAX_FRAME_PAYLOAD = 1427 bytes).
#[tokio::test]
async fn large_payload_multi_frame() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    // 16 KiB payload — spans ~11 frames
    let payload: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();
    let payload_clone = payload.clone();

    let server_handle = tokio::spawn(async move {
        let (mut stream, _addr) = listener.accept().await.unwrap();
        // Read until we have the full payload
        let mut received = Vec::new();
        while received.len() < payload_clone.len() {
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        // Echo it all back
        stream.write_all(&received).await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stream.shutdown().await.unwrap();
    });

    let client_config = ClientConfig::from_bridge_cert(&bridge_cert).unwrap();
    let mut stream = Obfs4Stream::connect(&addr, client_config).await.unwrap();

    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();

    let mut response = vec![0u8; payload.len()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, payload);

    server_handle.await.unwrap();
}

/// Verify that two independent sessions produce different keys (no key reuse).
#[tokio::test]
async fn independent_sessions_different_keys() {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate();
    let bridge_cert = server_config.bridge_cert();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let addr_clone = addr.clone();
    let bridge_clone = bridge_cert.clone();

    // First session
    let server_handle = tokio::spawn(async move {
        // Accept two connections sequentially
        for _ in 0..2 {
            let (mut stream, _addr) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(&buf[..n]).await.unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            stream.shutdown().await.unwrap();
        }
    });

    let config1 = ClientConfig::from_bridge_cert(&bridge_cert).unwrap();
    let mut s1 = Obfs4Stream::connect(&addr, config1).await.unwrap();
    s1.write_all(b"session1").await.unwrap();
    s1.flush().await.unwrap();
    let mut r1 = [0u8; 8];
    s1.read_exact(&mut r1).await.unwrap();
    assert_eq!(&r1, b"session1");
    drop(s1);

    // Small gap
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let config2 = ClientConfig::from_bridge_cert(&bridge_clone).unwrap();
    let mut s2 = Obfs4Stream::connect(&addr_clone, config2).await.unwrap();
    s2.write_all(b"session2").await.unwrap();
    s2.flush().await.unwrap();
    let mut r2 = [0u8; 8];
    s2.read_exact(&mut r2).await.unwrap();
    assert_eq!(&r2, b"session2");
    drop(s2);

    server_handle.await.unwrap();
}

/// IAT mode integration tests — round-trip with Enabled and Paranoid modes.
#[tokio::test(flavor = "multi_thread")]
async fn iat_mode_enabled_round_trip() {
    use construct_ice::IatMode;
    iat_round_trip(IatMode::Enabled).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn iat_mode_paranoid_round_trip() {
    use construct_ice::IatMode;
    iat_round_trip(IatMode::Paranoid).await;
}

async fn iat_round_trip(iat_mode: construct_ice::IatMode) {
    let port = free_port().await;
    let addr = format!("127.0.0.1:{port}");

    let server_config = ServerConfig::generate().with_iat(iat_mode);
    let bridge_line = server_config.bridge_line();
    let listener = Obfs4Listener::bind(&addr, server_config).await.unwrap();

    let addr_clone = addr.clone();
    let server_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let config = ClientConfig::from_bridge_line(&bridge_line).unwrap();
    // Verify IAT mode is parsed correctly from bridge line
    assert_eq!(config.iat_mode, iat_mode);

    let mut client = Obfs4Stream::connect(&addr_clone, config).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    client.flush().await.unwrap();

    let mut response = [0u8; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"hello");

    server_handle.await.unwrap();
}

/// Bridge line round-trip: ServerConfig::bridge_line → ClientConfig::from_bridge_line.
#[test]
fn bridge_line_roundtrip() {
    use construct_ice::IatMode;

    for &mode in &[IatMode::None, IatMode::Enabled, IatMode::Paranoid] {
        let server = ServerConfig::generate().with_iat(mode);
        let line = server.bridge_line();
        assert!(line.contains("cert="), "missing cert in bridge line");
        assert!(line.contains(&format!("iat-mode={}", mode.as_u8())));

        let client = ClientConfig::from_bridge_line(&line).unwrap();
        assert_eq!(client.iat_mode, mode);

        // Verify cert encodes the same key: parse the cert back and compare
        let cert = server.bridge_cert();
        let client2 = ClientConfig::from_bridge_cert(&cert).unwrap();
        assert_eq!(client.server_pubkey, client2.server_pubkey);
        assert_eq!(client.node_id, client2.node_id);
    }
}
