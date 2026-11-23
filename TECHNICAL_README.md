# Remote Biometric Authenticator — Technical README

## Technology direction

This project is split into two native implementations:

- **Linux:** Rust
- **Android:** Kotlin + regular Android SDK + Jetpack Compose

The two implementations communicate through a **language-independent authentication protocol**. The protocol is specified separately from either implementation and validated with shared test vectors.

The project supports two transport backends:

- **Wi-Fi / IP**, discovered with mDNS/DNS-SD
- **Bluetooth Low Energy**, using GATT

Both transports use the same authentication protocol and security model.

---

## Repository layout

```text
rba/
│
├── protocol/
│   ├── specification/        # Language-independent protocol spec
│   └── test-vectors/         # Shared conformance fixtures
│
├── linux/
│   ├── protocol/             # Rust protocol, crypto, framing
│   ├── rbad/                 # Rust daemon
│   ├── rba/                  # Rust CLI
│   ├── rba-sim/              # Simulated authenticator
│   ├── pam-rba/              # Thin PAM adapter
│   ├── polkit-agent/         # Optional headless polkit agent
│   └── systemd/              # rbad.service and rbad.socket
│
├── android/
│   ├── protocol/             # Kotlin protocol implementation
│   └── app/                  # Compose UI, Keystore, transports
│
├── packaging/
│   ├── debian/
│   ├── arch/
│   ├── fedora/
│   └── opensuse/
│
├── tests/                    # End-to-end, PAM, sudo, polkit scripts
│
└── docs/
```

---

# Linux technology stack

## Language

Use **Rust** for the Linux implementation.

Rust is the preferred language for the security-sensitive daemon because it avoids a large class of memory-safety bugs while providing good access to Linux system APIs.

The primary Rust components are:

```text
rbad
rba
transport implementations
protocol implementation
cryptographic verification
pairing/device management
local IPC
policy enforcement
```

## Main daemon

The main process is:

```text
rbad
```

Responsibilities:

- device discovery
- pairing
- device identity management
- Wi-Fi transport
- Bluetooth transport
- TLS/session establishment where applicable
- authentication protocol
- signature verification
- challenge generation
- replay prevention
- request-context verification
- device revocation
- audit logging
- local IPC for PAM and other trusted integrations

The daemon should run with the minimum privileges needed.

Do not put all of this functionality inside PAM.

---

# PAM integration

Build:

```text
pam_rba.so
```

as a **very thin adapter**.

The PAM module should:

1. obtain the PAM authentication context
2. verify the local username/context
3. communicate with `rbad`
4. wait for the authentication result
5. return the appropriate PAM result

It should **not** directly implement:

- Wi-Fi networking
- Bluetooth
- mDNS
- pairing
- cryptographic protocol logic
- Android communication
- complex device management

Architecture:

```text
PAM
 │
 ▼
pam_rba.so
 │
 ▼
rbad
 │
 ├── Wi-Fi
 └── Bluetooth
```

This keeps PAM failure modes and ABI compatibility issues isolated from the main application.

---

# Local Linux IPC

PAM should communicate with `rbad` over a protected local IPC mechanism.

Preferred options include:

- Unix domain socket with `SO_PEERCRED`
- D-Bus where appropriate
- systemd socket activation where useful

The daemon must authenticate the local caller.

Do not trust an arbitrary username supplied by an unprivileged client.

For example:

```text
PAM says:
    local caller = alice

request says:
    user = alice

=> valid
```

but:

```text
PAM says:
    local caller = alice

request says:
    user = root

=> reject
```

---

# Linux dependencies

The Linux application should use **distribution-managed system dependencies** instead of shipping duplicate copies of system libraries.

Cargo is used for Rust development/builds, but packaging should integrate with the native package ecosystem of each distribution.

Where appropriate, use distro-provided:

- BlueZ
- Avahi / mDNS implementation
- PAM
- polkit
- systemd
- D-Bus
- libfprint
- TLS/native crypto dependencies where packaging policy calls for them

Avoid embedding or vendoring system libraries unnecessarily.

The exact Rust crate dependencies should be reviewed against the policies of each target distribution.

---

# Linux package formats

Do not refer to `.dnf` as a package format.

`dnf` is a package manager.

Typical targets are:

| Distribution family | Package |
|---|---|
| Debian / Ubuntu | `.deb` |
| Arch Linux | `.pkg.tar.zst` |
| Fedora / RHEL | `.rpm` |
| openSUSE | `.rpm` |

Packaging should be native to the distribution.

Examples:

```text
Debian:
    Debian packaging metadata
    -> .deb

Arch:
    PKGBUILD
    -> .pkg.tar.zst

Fedora:
    RPM spec
    -> .rpm

openSUSE:
    RPM/spec or OBS packaging
    -> .rpm
```

Do not bundle a universal binary package containing private copies of core Linux services and libraries just to simplify distribution.

---

# Android technology stack

## Language

Use:

```text
Kotlin
```

with the regular Android SDK.

## UI

Use:

```text
Jetpack Compose
```

The UI should stay intentionally minimal.

Example:

```text
┌───────────────────────────┐
│                           │
│  Linux authentication     │
│                           │
│  User: alice              │
│  Host: workstation        │
│  Action: sudo             │
│                           │
│  [ Authenticate ]         │
│                           │
└───────────────────────────┘
```

The Android application should not implement its own fingerprint or face recognition.

Use the Android system biometric stack.

---

# Android authentication

Use:

```text
AndroidX BiometricPrompt
```

for biometric interaction.

Use:

```text
Android Keystore
```

for the private authentication key.

Conceptually:

```text
Linux challenge
       │
       ▼
Android app
       │
       ▼
BiometricPrompt
       │
       ▼
user authenticates
       │
       ▼
Android Keystore
       │
       ▼
sign challenge/context
       │
       ▼
Linux
```

The private key must remain non-exportable.

The application never receives:

- fingerprint images
- face images
- biometric templates

The Android platform handles those.

---

# Android security policy

The preferred authentication class for the cryptographic signing key is:

```text
BIOMETRIC_STRONG
```

Do not silently downgrade to a weaker biometric modality.

Device credential support can be added as an explicit policy option later.

The application should account for differences between Android devices:

- hardware-backed Keystore availability
- StrongBox availability
- biometric class
- biometric enrollment changes

Do not assume all Android devices provide identical security guarantees.

---

# Android minimum SDK

Recommended baseline for a new security-focused implementation:

```text
minSdk = 28
```

Use the current supported Android SDK for:

```text
compileSdk
targetSdk
```

Do not pin an obsolete target SDK just for compatibility.

If older Android versions are supported later, add them deliberately with a tested security/feature matrix instead of weakening the core design.

---

# Android networking

## Wi-Fi

Use Android's Network Service Discovery APIs for mDNS/DNS-SD discovery.

Example service:

```text
_rba._tcp.local.
```

mDNS is only discovery.

It does **not** establish trust.

After discovery:

```text
mDNS
  ↓
candidate endpoint
  ↓
TLS / authenticated session
  ↓
remote authentication protocol
```

The discovered hostname, IP address, MAC address, or service name must never be treated as the device's cryptographic identity.

## Bluetooth

Use the Android Bluetooth LE / GATT APIs.

Bluetooth is another transport adapter for the same authentication protocol.

```text
Wi-Fi:
    IP/TLS
       ↓
    Auth Protocol

BLE:
    GATT
       ↓
    Auth Protocol
```

Do not create a weaker or separate security protocol specifically for BLE.

---

# Protocol implementation

The protocol is **not a shared Rust/Kotlin library**.

Rust and Kotlin are different implementation environments.

Instead:

```text
protocol specification
        │
        ├───────────────┐
        ▼               ▼
      Rust            Kotlin
     Linux            Android
```

The protocol specification must define:

- message types
- field encoding
- canonicalization rules
- field ordering
- supported algorithms
- protocol versions
- challenge semantics
- request expiration
- request IDs
- device IDs
- signature input
- error codes
- state transitions

Use shared **test vectors** to ensure the Rust and Kotlin implementations produce and validate identical results.

This is preferable to tightly coupling the two sides around a shared source-language dependency.

---

# Serialization

Do not sign arbitrary JSON serialization.

The signature must operate on a canonical representation.

Suitable approaches include:

- deterministic/canonical CBOR
- a carefully defined binary format
- another serialization format with an explicit canonical encoding

If JSON is used for human-readable debugging, it should not be the cryptographic representation unless canonicalization is explicitly defined and rigorously implemented.

---

# Cryptography

Do not implement cryptographic primitives manually.

Use established libraries for:

- public-key signatures
- TLS
- random-number generation
- hashing
- key derivation if required

The protocol should use standard, well-reviewed algorithms.

Initial design target:

```text
asymmetric identity key
+
fresh random challenge
+
context-bound signature
+
authenticated transport
```

Do not use:

```text
YES / NO
```

as the security decision.

The signed response is the proof.

---

# Device identity

Linux stores the Android device's public identity.

Android stores the Linux host identity.

Prefer:

```text
Android:
    non-exportable private device-auth key
    public device identity

Linux:
    trusted Android public key
    host identity
```

rather than:

```text
shared password copied to both devices
```

The device public key is the authenticator identity.

Never derive identity from:

- IP address
- hostname
- Android device name
- Bluetooth MAC address
- mDNS name
- BLE service UUID

---

# Pairing

Pairing must be explicit.

Recommended model:

```text
Linux enters pairing mode
        ↓
short-lived pairing session
        ↓
display code / QR / fingerprint
        ↓
Android verifies matching code
        ↓
keys exchanged
        ↓
user confirms
        ↓
device becomes trusted
        ↓
pairing mode expires
```

mDNS or BLE discovery must never automatically authorize a device.

Linux should be able to list, revoke, and rename paired devices.

Example:

```text
Paired authenticators:

Pixel 9
  ID: 7e8f...
  Public key: SHA256:...
  Status: paired
```

---

# Authentication request

The request must identify exactly what the Android user is approving.

Conceptually:

```json
{
  "protocol_version": 1,
  "request_id": "...",
  "host_id": "...",
  "device_id": "...",
  "user": "alice",
  "purpose": "sudo",
  "service": "sudo",
  "operation": "authenticate",
  "challenge": "...",
  "issued_at": 0,
  "expires_at": 0
}
```

The exact encoding is defined by the protocol specification.

The signature must bind at minimum:

```text
protocol version
host identity
device identity
request ID
username
purpose
service
operation
challenge
expiration
```

Use a protocol/domain separator such as:

```text
RBA_AUTH_V1
```

to prevent cross-protocol signing confusion.

---

# Replay protection

Every authentication request requires a fresh cryptographic challenge.

Linux must reject:

- expired challenges
- reused request IDs
- reused challenges
- wrong host identity
- wrong device identity
- wrong username
- wrong purpose
- wrong operation
- invalid signatures

A successful response from an earlier authentication must not be reusable for a later request.

---

# Transport independence

Transport is not security identity.

The final architecture is:

```text
                       AUTH PROTOCOL
                            │
                 ┌──────────┴──────────┐
                 │                     │
               Wi-Fi                  BLE
                 │                     │
           mDNS + TLS               GATT
                 │                     │
                 └──────────┬──────────┘
                            │
                            ▼
                       rbad
```

Changing from Wi-Fi to Bluetooth should not change:

- device identity
- signature algorithm
- challenge rules
- replay protection
- authorization context
- pairing identity

Only the transport changes.

---

# polkit

polkit should be treated separately from PAM.

PAM answers:

```text
Did this user authenticate?
```

polkit answers:

```text
Is this user authorized for this action?
```

For actions such as:

```text
org.freedesktop.systemd1.manage-units
```

the Android authenticator should participate in the authentication step used by the polkit flow.

Do not treat the polkit action itself as a PAM module.

---

# fprintd / libfprint

fprintd/libfprint support is a later compatibility project.

Do not make the main system pretend that Android is literally a USB fingerprint reader.

Core architecture:

```text
Android biometric
        ↓
rbad
        ↓
PAM / polkit
```

Optional future compatibility:

```text
Android
   ↓
rbad
   ↓
fprint compatibility adapter
   ↓
fprintd / libfprint
```

This distinction matters because Android may authenticate with:

- fingerprint
- face
- device credential

whereas the Linux fingerprint stack is specifically designed around fingerprint devices.

The generic authenticator should therefore remain generic.

---

# FIDO2 consideration

FIDO2/CTAP2 should remain an architectural consideration because it provides a standards-based model for hardware-backed cryptographic authentication.

Conceptually:

```text
Android biometric
       ↓
hardware-backed credential
       ↓
cryptographic authenticator
       ↓
Linux
```

However, direct PAM/polkit integration may still justify the project's own protocol.

Do not add FIDO2 merely for branding or complexity. Add it if it solves a concrete interoperability problem.

---

# Packaging architecture

The Linux package should install:

```text
rbad
rba
pam_rba.so
systemd service/socket files
polkit integration files
configuration files
documentation
```

The package should also declare runtime dependencies through the native package manager.

The installer must not silently overwrite a user's PAM configuration in an unsafe way.

For PAM installation:

- preserve existing configuration
- validate configuration
- provide rollback
- preserve a known recovery path
- avoid locking the user out during upgrades

---

# Build model

## Linux development

Use Cargo:

```bash
cargo build
cargo test
cargo clippy
```

The project can use a Cargo workspace:

```text
linux/
  Cargo.toml
  rbad/
  rba/
  pam-rba/
```

The final distro build should follow the distribution's packaging/build rules.

## Android development

Use Gradle with the normal Android toolchain:

```text
Kotlin
Android Gradle Plugin
Android SDK
Jetpack Compose
AndroidX
```

Example build:

```bash
./gradlew assembleDebug
```

Release builds should use Android's normal signing/release process.

Do not ship debug builds as production authenticators.

---

# Quality and security tooling

## Rust

At minimum:

```text
cargo test
cargo fmt --check
cargo clippy
```

Add security/dependency auditing appropriate to the project's distribution pipeline.

## Android

At minimum:

```text
unit tests
instrumentation tests
lint
Compose/UI tests
```

Test on multiple Android security configurations.

---

# Cross-language protocol tests

Protocol test vectors should cover:

- valid request
- valid signature
- invalid signature
- wrong device
- wrong host
- wrong user
- wrong purpose
- wrong operation
- expired request
- replayed request
- malformed message
- unsupported protocol version
- unknown mandatory field
- canonical encoding edge cases

Both Rust and Kotlin implementations should consume the same fixtures.

---

# Initial implementation order

Do this in this order:

### 1. Protocol specification

Define:

```text
messages
canonical encoding
cryptographic algorithms
challenge semantics
request context
signature format
errors
state machines
```

### 2. Rust daemon

Build:

```text
rbad
```

with Wi-Fi transport first.

### 3. Fake Android client

Build a test client using a test private key.

This allows the complete network/crypto path to be tested before Android UI work.

### 4. Minimal Android application

Add:

```text
Jetpack Compose
BiometricPrompt
Android Keystore
mDNS
Wi-Fi transport
```

### 5. PAM

Add:

```text
pam_rba.so
```

as a thin adapter.

### 6. polkit

Integrate the authenticator into the appropriate desktop authorization flow.

### 7. Bluetooth

Add BLE/GATT as another transport for the existing protocol.

### 8. fprint compatibility

Investigate only after the previous layers are stable.

---

# First end-to-end target

The first meaningful milestone is:

```bash
$ rba devices
```

Output:

```text
Paired authenticators:

  Pixel 9
  id: 7e8f...
  transport: wifi
  status: available
```

Then:

```bash
$ rba auth --user alice --purpose sudo
```

Output:

```text
Waiting for authentication on Pixel 9...
Authenticated.
```

This must already use:

- mDNS
- authenticated/encrypted network communication
- asymmetric device identity
- a fresh challenge
- Android-side key protection
- a cryptographic signature
- replay protection
- request-context binding

before PAM is added.

Then:

```bash
sudo -k
sudo id
```

should use the exact same authentication engine through PAM.

---

# Security baseline

The project is considered to have the intended security architecture only when the following chain holds:

```text
Android biometric authentication
          +
Android Keystore private key
          +
explicit device pairing
          +
fresh challenge
          +
request-context binding
          +
cryptographic signature
          +
authenticated transport
          +
Linux-side policy
```

Wi-Fi and Bluetooth are transport mechanisms.

mDNS and BLE advertisements are discovery mechanisms.

The Android public key is the device identity.

The signed challenge response is the authentication proof.

PAM and polkit remain separate policy/integration layers.

---

# Important implementation rule

When implementation convenience conflicts with the security model, do not silently weaken the design.

Examples:

- Do not replace asymmetric identity with a static shared password just because pairing is easier.
- Do not accept any mDNS result without identity verification.
- Do not trust a BLE MAC address as identity.
- Do not reuse old authentication signatures.
- Do not let PAM parse or execute complex network protocol logic.
- Do not store private keys in normal Android application storage.
- Do not silently downgrade biometric strength.
- Do not make fprintd compatibility a dependency of the core authenticator.

Prefer a small amount of extra engineering over a weaker authentication boundary.
