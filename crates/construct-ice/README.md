# construct-ice

obfs4 pluggable transport implementation in Rust for Construct messenger.

Makes gRPC traffic indistinguishable from random noise — resistance against DPI systems
used in censorship (Iran, China, Russia).

## Status

| Component | Status |
|-----------|--------|
| Elligator2 encode/decode | ✅ Randomized variant, Go cross-tested (10 vectors) |
| Keypair generation | ✅ Dirty pubkey from representative |
| ntor handshake crypto | ✅ Go cross-tested (KEY_SEED, AUTH) |
| KDF (HKDF-SHA256) | ✅ Go cross-tested (144-byte session keys) |
| Handshake (client + server) | ✅ Mark scanning, MAC with clock skew |
| Frame encoder/decoder | ✅ NaCl secretbox + SipHash OFB length obfuscation |
| AsyncRead/AsyncWrite transport | ✅ Obfs4Stream, Obfs4Listener |
| E2E tests | ✅ Echo, multi-round-trip, large payload, multi-session |
| tonic/hyper integration | ⏳ planned (Obfs4Stream is compatible) |
| iOS interop | ⏳ planned |

## Architecture

```
[iOS gRPC] ↔ [obfs4 client] ~~~ obfuscated TCP ~~~ [obfs4 server] ↔ [Traefik/Envoy]
```

```
src/
  crypto/
    elligator2.rs    ← Curve25519 ↔ random bytes (Randomized variant)
    keypair.rs       ← ephemeral keypair with Elligator2 retry loop
    ntor.rs          ← ntor handshake key exchange (double DH)
    kdf.rs           ← HKDF-SHA256 → 144-byte session key block
  handshake/
    client.rs        ← client handshake state machine
    server.rs        ← server handshake + mark scanning + anti-probing
  framing/
    encoder.rs       ← NaCl secretbox frame encryption
    decoder.rs       ← frame decryption + MAC verification
    length_dist.rs   ← SipHash-2-4 OFB length obfuscation
  transport/
    mod.rs           ← Obfs4Stream (AsyncRead+AsyncWrite), Obfs4Listener
```

## Usage

### Client
```rust
use construct_obfs4::{ClientConfig, Obfs4Stream};

let config = ClientConfig::from_bridge_cert("base64_bridge_cert")?;
let mut stream = Obfs4Stream::connect("relay.example.com:443", config).await?;
// stream implements AsyncRead + AsyncWrite — pass to tonic/hyper
```

### Server
```rust
use construct_obfs4::{ServerConfig, Obfs4Listener};

let config = ServerConfig::generate();
println!("Bridge cert: {}", config.bridge_cert()); // distribute to clients
let listener = Obfs4Listener::bind("0.0.0.0:443", config).await?;
while let Ok((stream, addr)) = listener.accept().await {
    tokio::spawn(async move { /* handle(stream) */ });
}
```

## Testing

```bash
# Run all tests (unit + E2E + doctests)
cargo test

# Run only Go cross-reference vector tests
cargo test go_reference

# Run E2E integration tests
cargo test --test e2e
```

## References

- [obfs4 spec](https://gitlab.com/yawning/obfs4/-/blob/master/doc/obfs4-spec.txt)
- [Elligator2 paper](https://elligator.cr.yp.to/elligator-20130828.pdf)
- [Go reference implementation](https://gitlab.com/yawning/obfs4)
- [curve25519-elligator2](https://docs.rs/curve25519-elligator2)
