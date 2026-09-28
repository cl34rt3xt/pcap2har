# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build --release                 # binary at target/release/pcap2har
cargo test                            # unit tests (in src/) + integration tests (tests/)
cargo test --test cli                 # one integration test file (cli, capture_pipeline, quic_vectors, http3_qpack, ...)
cargo test --lib tcp::                # unit tests in one module
cargo test some_test_name             # tests matching a name
cargo run -- capture.pcapng --keylog sslkeys.log -o out.har
```

MSRV is Rust 1.88. CI (`.github/workflows/build.yml`) only runs release builds for x86_64 Linux across several Ubuntu versions; it does not run tests. Several crypto and parsing dependencies are pinned with `=x.y.z` in `Cargo.toml`, so don't loosen them casually.

## Architecture

The library crate (`src/lib.rs`) does the work, and `src/main.rs` is a thin CLI over `convert_capture`. The CLI turns `--max-memory-mib` and `--max-body-mib` into a `DecodeLimits`: stream, segment and connection caps grow with the body cap, and every cap is clamped to the memory budget. With `--strict`, the process exits with code 2 when any non-Info diagnostic is present. The HAR goes to stdout or `-o`, and diagnostics and stats go to stderr.

### Data flow (`src/pipeline.rs`)

1. **`capture/`**: `CaptureReader` parses PCAP/PCAPNG in pure Rust, with no libpcap at runtime. It first builds a `CaptureIndex`, which collects NSS secrets from pcapng Decryption Secrets Blocks and from the `--keylog` sidecar into a `SecretStore`. It then streams packets. `LinkDecoder` normalizes the link layers (Ethernet/VLAN, Linux SLL/SLL2, raw IP) into `TransportPacket::Tcp` or `TransportPacket::Udp`. IP fragments are rejected.
2. **TCP path**: `tcp::TcpReassembler` buffers segments per direction (`StreamKey`) and handles retransmissions. When the capture has been fully read, `converter::Converter::process_streams_with_tls` runs over all the reassembled streams:
   - Streams that look like TLS: it pulls client/server random and cipher suite from the handshake records, decrypts with TLS 1.3 traffic secrets or a TLS 1.2 master secret (`tls.rs`), then parses the plaintext as HTTP/2 (`http2.rs`, HPACK) or HTTP/1.x.
   - Other streams go to `process_streams`, which tries HTTP/1.x first (`http.rs`, with chunked and gzip/deflate decoding) and then FastCGI (`fcgi.rs`).
   - Requests and responses are paired by reversing the `StreamKey`: by position for HTTP/1 keep-alive, by stream ID for HTTP/2.
3. **UDP/QUIC path**: `quic::QuicPassiveDecoder` is fed every datagram as it arrives. It covers QUIC v1/v2 packet protection, CID tracking and migration, Retry, key updates, and CRYPTO/STREAM reassembly with a shared byte budget. At `finish()` it emits `QuicEvent`s. The pipeline then groups the `StreamData` and `StreamFinished` events by connection into `http3::Http3Session`s. Each session routes streams, decodes HTTP/3 frames and QPACK (through `compcol`), and produces `NormalizedExchange`s.
4. **Output**: both paths end up as `exchange::NormalizedExchange`, the protocol-neutral model. `Converter::to_har` builds the `har.rs` structs from these exchanges: URL, cookies, query string, postData, and a body that is either text or base64. The result is wrapped in a `ConversionReport` along with diagnostics and stats.

### Conventions that span modules

- **Everything is bounded by `DecodeLimits`** (`options.rs`). New buffering must be charged against the relevant cap. When a cap is hit, emit a `DiagnosticCode::ResourceLimit` diagnostic (or truncate the body) instead of failing. `DecodeLimits::testing()` returns small limits for tests that exercise the caps. The unit test in `lib.rs` asserts the default values, so update it when a default changes.
- **Partial conversion is reported through `Diagnostic`, not as an error.** `ConversionError` covers only capture-level failures. Diagnostics carry a severity, a code and a scope (capture, datagram, connection, packet or stream), and the pipeline limits how many it keeps. If you add a new `DiagnosticCode`, also add its name mapping in `main.rs`.
- **Output must be deterministic.** HashMap-keyed streams are sorted before processing, and FastCGI headers are sorted. Keep this in mind when adding iteration over maps.
- **Secrets**: the types in `secrets.rs` zeroize on drop, and their `Debug` impls hide the key material. Keep both properties. Conflicting secrets for the same client random keep the first value and emit a diagnostic.
- **Body encoding**: `content.text` is plain text only when the MIME type is text-like and the body is valid UTF-8. Otherwise it is base64. Only HTTP/1.x and FastCGI bodies are decompressed. HTTP/2 and HTTP/3 bodies are emitted as captured.
- `convert_pcap_to_har` and `normalized_exchanges_to_har` are kept for older callers (see `tests/capture_compat.rs`, `tests/tls_legacy_compat.rs`). New code should use `convert_capture`.

### Tests

- `tests/support/capture.rs` builds synthetic PCAP/PCAPNG files in memory (Ethernet/SLL framing, IPv4/IPv6 TCP/UDP, DSB blocks, several sections, big-endian files) and writes them to a `TempCapture`. Integration tests are built on these helpers rather than on checked-in capture files.
- `tests/cli.rs` runs the built binary through `CARGO_BIN_EXE_pcap2har`.
- RFC test vectors in `tests/vectors/` (RFC 9001 and RFC 9369 for QUIC Initial keys and packets, RFC 9204 for QPACK) are loaded with `include_str!`.
- `tests/quic_http3_fixture.rs` reads a real Chromium capture from `.superpowers/artifacts/quic/`. If that file is missing, the test returns early and passes without checking anything.
