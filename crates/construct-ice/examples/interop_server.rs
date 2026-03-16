//! Minimal obfs4 server for local interop testing.
//! Usage: cargo run --example interop_server -- 0.0.0.0:54321

use construct_ice::{Obfs4Listener, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:54321".to_string());
    let config = ServerConfig::generate();

    println!("obfs4 server starting on {addr}");
    println!("Bridge cert: {}", config.bridge_cert());

    let listener = Obfs4Listener::bind(&addr, config).await?;

    loop {
        let (mut stream, peer) = listener.accept().await?;
        println!("Accepted connection from {peer}");

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        println!("Received {} bytes, echoing back", n);
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                    Err(e) => {
                        eprintln!("Read error: {e}");
                        break;
                    }
                }
            }
        });
    }
}
