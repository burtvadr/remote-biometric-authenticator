# Rust portability inventory

Static source classification; not a cross-platform compile guarantee. PORTABLE means no direct Linux-only requirement identified in the file; HYBRID means portable logic with platform coupling or behavior; PLATFORM-SPECIFIC means the current role requires OS APIs.

| File (under linux/) | Classification | Purpose / rationale |
|---|---|---|
| `pam-rba/src/ipc.rs` | PLATFORM-SPECIFIC | Unix socket client and peer verification |
| `pam-rba/src/lib.rs` | PLATFORM-SPECIFIC | PAM C ABI and Linux integration |
| `polkit-agent/src/main.rs` | PLATFORM-SPECIFIC | polkit and D-Bus session integration |
| `protocol/src/bin/vecgen.rs` | PORTABLE | Generate shared protocol vectors |
| `protocol/src/cbor.rs` | PORTABLE | Canonical encoding and decoding |
| `protocol/src/crypto.rs` | PORTABLE | Cryptographic primitives |
| `protocol/src/errors.rs` | PORTABLE | Protocol errors |
| `protocol/src/frame.rs` | PORTABLE | Wire framing |
| `protocol/src/lib.rs` | PORTABLE | Protocol exports and clock |
| `protocol/src/messages.rs` | PORTABLE | Wire messages |
| `protocol/src/nonce.rs` | PORTABLE | Replay tracking |
| `protocol/src/pairing.rs` | PORTABLE | Enrollment transcript and confirmation |
| `protocol/src/ratelimit.rs` | PORTABLE | Sliding window and state persistence |
| `protocol/src/types.rs` | PORTABLE | Wire types and constants |
| `protocol/src/verifier.rs` | PORTABLE | Response verification |
| `protocol/tests/vectors.rs` | PORTABLE | Shared fixture conformance; repository layout assumption |
| `rba-sim/src/device.rs` | HYBRID | Simulated authenticator; conditional Unix file permission enforcement |
| `rba-sim/src/lib.rs` | PORTABLE | Simulator exports; device module has platform-specific storage behavior |
| `rba-sim/src/main.rs` | HYBRID | Simulator CLI and daemon interaction; dependency portability not proven |
| `rba/src/main.rs` | HYBRID | CLI, Unix control IPC and Linux daemon integration |
| `rba/src/pam.rs` | PLATFORM-SPECIFIC | Linux PAM configuration |
| `rbad/src/audit.rs` | PORTABLE | Structured audit events and file output |
| `rbad/src/authz.rs` | PORTABLE | Pure authorization evaluator; proposed new module |
| `rbad/src/config.rs` | HYBRID | Configuration and Unix private-file helpers |
| `rbad/src/engine.rs` | HYBRID | Session, enrollment and verification orchestration; coupled to registry and transport |
| `rbad/src/ipc.rs` | PLATFORM-SPECIFIC | Linux peer credentials and NSS lookups; wire types could be extracted |
| `rbad/src/lib.rs` | HYBRID | Daemon bootstrap; Linux hostname fallback |
| `rbad/src/main.rs` | HYBRID | Daemon lifecycle and Linux signal/service integration |
| `rbad/src/registry.rs` | HYBRID | Credential state and Unix-backed persistence |
| `rbad/src/server.rs` | PLATFORM-SPECIFIC | Unix control listener and peer admission; portable dispatch could be extracted |
| `rbad/src/tls.rs` | HYBRID | TLS identity and certificate persistence; host storage coupling |
| `rbad/src/transport/ble.rs` | PORTABLE | BLE framing and segmentation; no BlueZ integration here |
| `rbad/src/transport/mod.rs` | HYBRID | Transport session orchestration coupled to daemon engine |
| `rbad/src/transport/wifi.rs` | HYBRID | TCP/TLS/mDNS plus host-specific networking details |
| `rbad/tests/security.rs` | HYBRID | Engine integration and Linux peer credential tests |

## Workspace dependency declarations

Cargo is unavailable. This is the direct manifest inventory, not a resolved Cargo metadata graph.

### pam-rba

- dependencies: libc, rba-protocol, rbad, serde, serde_json

### rba-polkit-agent

- dependencies: futures-util, rba-protocol, rbad, serde, serde_json, tokio, tracing, tracing-subscriber, zbus

### rba-protocol

- dependencies: base64, getrandom, hex, hkdf, hmac, p256, rand_core, serde_json, sha2, tokio, zeroize
- dev-dependencies: hex, serde_json

### rba

- dependencies: libc, rba-protocol, rbad, serde, serde_json, tokio

### rba-sim

- dependencies: base64, hex, p256, rba-protocol, rustls, rustls-pemfile, serde, serde_json, tokio, tokio-rustls

### rbad

- dependencies: getrandom, hex, libc, mdns-sd, p256, rand_core, rba-protocol, rcgen, rustls, rustls-pemfile, serde, serde_json, sha2, tokio, tokio-rustls, zeroize
- dev-dependencies: hex, rba-protocol, rba-sim, serde_json

The authorization module now uses `PrincipalId`, `Scope` and exact `Grant` set membership. It remains free of OS, network, filesystem and cryptographic I/O. Linux NSS canonical identity resolution and administrative peer checks remain in IPC/server integration. The enclosing daemon is still Linux-specific.
