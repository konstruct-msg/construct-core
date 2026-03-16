//! Minimal obfs4 client for local interop testing.
//! Usage: cargo run --example interop_client -- <addr> <bridge_cert>

use construct_ice::{ClientConfig, Obfs4Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:54321".to_string());
    let cert = std::env::args().nth(2).unwrap_or_else(|| {
        eprintln!("Usage: interop_client <addr> <bridge_cert_base64>");
        std::process::exit(1);
    });
    println!("Connecting to obfs4 server at {addr}...");

    let config = ClientConfig::from_bridge_cert(&cert)?;
    let mut stream = Obfs4Stream::connect(&addr, config).await?;

    stream.write_all(b"hello from construct-ice").await?;

    let mut response = [0u8; 64];
    let n = stream.read(&mut response).await?;
    println!("Server echoed: {:?}", &response[..n]);

    Ok(())
}
