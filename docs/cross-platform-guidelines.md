# Cross-Platform Guidelines: Android ↔ iOS (and other ports)

This project is **Linux-first** with Android as the primary mobile platform.
iOS, macOS, and BSD are **not supported** and no code is written for them.
However, the codebase is structured so that a future iOS port can share
the maximum amount of non-UI logic with minimal friction.

## 1. What IS shared (already works on iOS with trivial adaptation)

| Layer | Status | iOS Effort |
|---|---|---|
| **Protocol** (canonical CBOR, P-256 signatures, TLS pinning, framing) | ✅ Rust, defined once | Recompile with ` cargo build --target aarch64-apple-ios ` |
| **Daemon core** (Engine, Registry, AuditLog, IPC socket, rate limits) | ✅ Rust, Linux-gated only where needed | Same binary; iOS just omits `#[cfg(target_os = "linux")]` guards |
| **Crypto** (EC Diffie-Hellman, SHA-256, CBOR encoding/decoding) | ✅ Rust `p256` + `zeroize` | Same |
| **Error codes & exit contracts** (0=paired, 1=failure, 2=usage) | ✅ Text output + stable exit codes | Re-implement in Swift/Objective‑C with same semantics |
| **Versioning policy** (two numbers: product vs protocol, 1.0.0 gate) | ✅ `docs/versioning.md` | Re-implement in project config |
| **Security audit entries** (SEC‑003 through SEC‑009) | ✅ `docs/security-audit.md` | Re-implement in project security doc |
| **Algorithm: address classification** (LAN vs VPN ranges) | ✅ Described in `transport/WifiTransport.kt` | Re-implement in Swift with same rules: 10/192.168/172.16‑31/fe80/fd00:: = LAN; 100.64.0.0/10 = VPN |
| **Algorithm: per‑address timeout + retry** | ✅ Described in roadmap + `WifiTransport.connect()` | Same duration, different `Timer` / `async‑await` |
| **Algorithm: candidate ranking** (LAN first, then VPN, de‑dup) | ✅ Described in `currentCandidates()` | Same logic, different collection type |
| **Algorithm: socket bind to Wi‑Fi Network** | ✅ Android `Network.bindSocket()` | iOS: `NWPathMonitor` + `NWTCPConnection` or `CFReadSocketStream`; same concept |
| **Pairing flow** (code entry → human gate → PAIRING_CONFIRMED → "Paired.") | ✅ Described in `rba pair` help + `docs/roadmap.md` | Same UI pattern: show code → wait for approval → success/failure |
| **CLI contracts** (`rba devices`, `rba status`, `rba auth`, `rba revoke`) | ✅ Text output + stable exit codes | Re-implement in Swift/CLI with same semantics |

## 2. What is PLATFORM‑SPECIFIC (must be reimplemented)

| Layer | Android | iOS | What changes |
|---|---|---|---|
| **Transport discovery** (mDNS/DNS‑SD) | ✅ `NsdManager` + `NsdServiceInfo` | ✅ `Browser` + `NSDServiceInfo` (Network framework) | Different APIs; same concept (announce/resolve service type) |
| **Transport connection** (TLS 1.3 socket) | ✅ `Socket()` + `SSLSocket` + manual pinning | ✅ `URLSession` + `TLSConfiguration` + `SecTrustEvaluator` | Same wire protocol, different SDK APIs |
| **Biometric consent** | ✅ `BiometricPrompt` (AndroidX) | ✅ `LAContext` + `SecAccessRef` (Keychain) | Different APIs, different UI patterns |
| **App distribution** | ✅ Google Play / internal tets | ✅ App Store / TestFlight | Different signing, different provisioning |
| **Key storage** | ✅ Android Keystore | ✅ iOS Keychain (`SecItemAdd/Query`) | Different APIs; same purpose (protect private key) |
| **Native UI** | ✅ Compose + Material Design | ✅ SwiftUI + Human Interface Guidelines | Complete rewrite — different frameworks, different design language |
| **Settings UI** | ✅ Android Settings activity | ✅ iOS Settings or in‑app `Form` | Different system integration |
| **Network callback** (re‑resolve on Wi‑Fi/VPN change) | ✅ `ConnectivityManager` + `NetworkCallback` | ✅ `NWPathMonitor` + `NWObserver` | Same goal, different Apple/Google APIs |
| **mdns_interface restriction** | ✅ Placeholder flag | ✅ Equivalent system flag or manual config | Same idea, different system settings |

## 3. Algorithmic Sharing (future developers can copy‑paste)

These are the **independent algorithms** that can be implemented once and reused:

### A. Address Classification
```
FUNCTION classify_address(addr):
    IF addr is IPv4:
        octets = addr.split('.').map(int)
        IF octets[0] == 10:                RETURN LAN
        IF octets[0] == 192 AND octets[1] == 168: RETURN LAN
        IF octets[0] == 172 AND octets[1] IN 16..31: RETURN LAN
        RETURN VPN
    IF addr is IPv6:
        IF addr starts with "fe80::" OR "fd": RETURN LAN
        RETURN VPN
    RETURN VPN
```

### B. Candidate Ranking (LAN first)
```
FUNCTION rank_candidates(raw_candidates):
    LAN = [c for c in raw_candidates if c.transport == LAN]
    VPN = [c for c in raw_candidates if c.transport == VPN]
    RETURN LAN sorted_by_ping ++ VPN sorted_by_ping
```

### C. Per‑Address Timeout Loop
```
FUNCTION try_candidates(candidates, timeout_ms, connect_fn):
    FOR each candidate IN candidates:
        started = now()
        WHILE now - started < timeout_ms:
            TRY connect_fn(candidate)
            IF success: RETURN success
            IF timeout: continue to next candidate
        END WHILE
    END FOR
    RETURN failure "all candidates exhausted"
```

### D. LAN‑First Preference with VPN Exclusion
```
FUNCTION build_candidate_list(mdns_results):
    candidates = []
    FOR each info IN mdns_results:
        FOR each addr IN info.addresses:
            transport = classify_address(addr)
            candidates.append(Candidate(addr, transport, info.host))
    RETURN rank_candidates(candidates)  // LAN first, then VPN
```

## 3. Repository Structure for Future Ports

```
remote-biometric-authenticator/
├── linux/              # Rust core (rba + rbad) — compiles to iOS with cargo
├── android/            # Kotlin UI + transport — ANDROID ONLY
├── docs/
│   ├── cross-platform-guidelines.md    ← THIS FILE
│   ├── versioning.md
│   ├── roadmap.md
│   └── security-audit.md
├── docs/roadmap.md    # Non-UI feature specs (shared algorithm descriptions)
└── README.md
```

## 4. Minimal iOS Porting Checklist (for someone who picks this up)

1. **Add iOS target**: `cargo install cargo-aapl` then `cargo build --target aarch64-apple-ios`
2. **Omit Linux gates**: Remove or gate `#[cfg(target_os = "linux")]` in `rba/` and `rbad/`
3. **Write iOS transport** (Swift):
   - mDNS/DNS‑D via `NWBrowser` (or `NSDManager` for compatibility)
   - TLS via `URLSession` with certificate pinning (same pin from pairing)
   - LAN/VPN classification using Algorithm A above
   - Candidate ranking using Algorithm B
   - Per-address timeout loop using Algorithm C
   - Socket bind to Wi‑Fi network (Apple equivalent of `wifiNetwork.bindSocket()`)
4. **Write iOS UI** (SwiftUI):
   - Code-entry screen (same as Android's `AuthPromptActivity`)
   - Biometric consent (LAContext + SecAccessRef)
   - Fallback to password entry
5. **Key storage** (Swift):
   - `SecItemAdd`/`SecItemCopyMatching` for the host public key and pairing code
   - Keychain sharing group if multiple apps need access
6. **Test**:
   - Pair over LAN (Wi‑Fi, no VPN)
   - Pair over VPN (Tailscale) — verify address ranking
   - Disable VPN, re‑pair — verify LAN is tried first
   - Simulate dead device — verify timeout + fallback to password

## 5. What This Project Will NOT Do

- ❌ No iOS/macOS/BSD code will be merged into this repo
- ❌ No `#ifdef` muddying the Linux core
- ❌ No dual‑licensing or universal binaries
- ❌ No shared UI code (Android Compose ≠ SwiftUI)
- ❌ No auto‑generated "write once, run anywhere" claims

## 6. Why This Matters

By keeping the **algorithms** (address classification, candidate ranking, timeout loops) and the **protocol** (CBOR + TLS + signed messages) completely platform‑agnostic, a future iOS port can be done in ~2–3 weeks of native Swift work instead of starting from scratch. The Rust core ( daemon + protocol) already compiles to iOS; the only new work is the two native transport layers and the native UI.

This document is the "handover map." Future contributors can read it, implement the 4 algorithms in their platform's language, and have a working iOS app that speaks the same protocol, uses the same pairing logic, and presents the same user‑experience contracts (`rba pair` → code → approval → "Paired.").

*Maintained for the life of this repository. Updated whenever the roadmap or protocol changes.*
