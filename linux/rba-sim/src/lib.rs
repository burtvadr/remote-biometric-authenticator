//! Device-side protocol implementation, shared by the `rba-sim` binary
//! and the Linux-side integration tests.
//!
//! This is the code an Android app would mirror with `BiometricPrompt` and
//! Android Keystore in place of the software key and the printed prompt.

pub mod device;

pub use device::{
    load_hosts, save_hosts, Behaviour, Device, DeviceKey, KnownHost, Misbehaviour, Presented,
};
