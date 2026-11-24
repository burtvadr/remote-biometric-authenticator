//! Portable enrollment primitive. No network, registry, Android or host OS API.
//!
//! The daemon and mobile client must not activate credentials until both
//! confirmations and the separate enrollment commit/receipt have completed.
#![forbid(unsafe_code)]

use pakery_core::crypto::CpaceGroup;
use pakery_crypto::{P256Group, Spake2P256};
use pakery_spake2::{PartyA, PartyAState, PartyB, PartyBState, Spake2Output};
use rand_core::CryptoRng;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

const PASSWORD_DOMAIN: &[u8] = b"RBA-ENROLLMENT-SPAKE2-PASSWORD-V2\0";
const CONTEXT_DOMAIN: &[u8] = b"RBA-ENROLLMENT-SPAKE2-P256-SHA256-V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidCode,
    InvalidContext,
    InvalidShare,
    RandomnessUnavailable,
    ExchangeFailed,
    ConfirmationFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidCode => "expected exactly six ASCII digits",
            Self::InvalidContext => "invalid enrollment context",
            Self::InvalidShare => "invalid SPAKE2 share",
            Self::RandomnessUnavailable => "enrollment randomness unavailable",
            Self::ExchangeFailed => "SPAKE2 exchange failed",
            Self::ConfirmationFailed => "SPAKE2 confirmation failed",
        })
    }
}

impl std::error::Error for Error {}

/// Deliberately not Clone, Debug, Display or Serialize. Only the local UI may
/// display the bytes; they must never appear in a protocol message or audit log.
pub struct PairingCode(Zeroizing<[u8; 6]>);

impl PairingCode {
    pub fn parse(input: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; 6] = input.try_into().map_err(|_| Error::InvalidCode)?;
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidCode);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn generate() -> Result<Self, Error> {
        // Reject the incomplete final interval; every six-digit code has the
        // same probability. This samples a password, not an SAS transcript.
        loop {
            let mut bytes = Zeroizing::new([0u8; 4]);
            getrandom::fill(&mut bytes[..]).map_err(|_| Error::RandomnessUnavailable)?;
            let mut value = u32::from_be_bytes(*bytes);
            if value >= 4_294_000_000 {
                value.zeroize();
                continue;
            }
            value %= 1_000_000;
            let mut digits = Zeroizing::new([b'0'; 6]);
            for digit in digits.iter_mut().rev() {
                *digit += (value % 10) as u8;
                value /= 10;
            }
            value.zeroize();
            return Ok(Self(digits));
        }
    }

    pub fn as_ascii(&self) -> &[u8; 6] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CodeEntry {
    DeviceTypes,
    HostTypes,
}

/// The two parties must obtain the same values independently. In particular,
/// the host computes its own TLS certificate hash; the phone computes the hash
/// of the actual peer certificate. Never trust a remotely claimed fingerprint.
/// Host is always SPAKE2 party A, regardless of which side displays the code.
#[derive(Clone)]
pub struct Context {
    pub session_id: [u8; 16],
    pub host_id: [u8; 16],
    pub device_id: [u8; 16],
    pub host_public_key: [u8; 65],
    pub device_public_key: [u8; 65],
    pub host_certificate_sha256: [u8; 32],
    pub expires_at: u64,
    pub code_entry: CodeEntry,
}

impl Context {
    fn aad(&self) -> Result<Vec<u8>, Error> {
        for key in [&self.host_public_key, &self.device_public_key] {
            if key[0] != 4 {
                return Err(Error::InvalidContext);
            }
            let point = P256Group::from_bytes(key).map_err(|_| Error::InvalidContext)?;
            if point.is_identity() {
                return Err(Error::InvalidContext);
            }
        }
        let mut aad = Vec::with_capacity(CONTEXT_DOMAIN.len() + 219);
        aad.extend_from_slice(CONTEXT_DOMAIN);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(&self.host_id);
        aad.extend_from_slice(&self.device_id);
        aad.extend_from_slice(&self.host_public_key);
        aad.extend_from_slice(&self.device_public_key);
        aad.extend_from_slice(&self.host_certificate_sha256);
        aad.extend_from_slice(&self.expires_at.to_be_bytes());
        aad.push(match self.code_entry {
            CodeEntry::DeviceTypes => 0,
            CodeEntry::HostTypes => 1,
        });
        Ok(aad)
    }
}

/// Hash-to-scalar profile for RBA's randomly generated, single-use passwords.
/// This does not replace SPAKE2's key schedule or confirmation functions.
/// A human-chosen reusable password is not supported by this interface's
/// enrollment policy and would require a different password-hardening profile.
fn password_scalar(code: PairingCode) -> Result<Zeroizing<<P256Group as CpaceGroup>::Scalar>, Error> {
    let mut hash = Sha512::new();
    hash.update(PASSWORD_DOMAIN);
    hash.update(code.as_ascii());
    let mut wide = hash.finalize();
    let scalar = P256Group::scalar_from_wide_bytes(&wide).map_err(|_| Error::ExchangeFailed);
    wide.as_mut_slice().zeroize();
    scalar.map(Zeroizing::new)
}

pub struct HostExchange(PartyAState<Spake2P256>);
pub struct DeviceExchange(PartyBState<Spake2P256>);

/// Caller supplies an OS-seeded cryptographic RNG. State is single-use and must
/// be dropped on cancellation, timeout, disconnect or malformed input.
pub fn start_host(
    code: PairingCode,
    context: &Context,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, HostExchange), Error> {
    let aad = context.aad()?;
    let scalar = password_scalar(code)?;
    let (share, state) = PartyA::<Spake2P256>::start(
        &scalar, &context.host_id, &context.device_id, &aad, rng,
    ).map_err(|_| Error::ExchangeFailed)?;
    Ok((share, HostExchange(state)))
}

pub fn start_device(
    code: PairingCode,
    context: &Context,
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, DeviceExchange), Error> {
    let aad = context.aad()?;
    let scalar = password_scalar(code)?;
    let (share, state) = PartyB::<Spake2P256>::start(
        &scalar, &context.host_id, &context.device_id, &aad, rng,
    ).map_err(|_| Error::ExchangeFailed)?;
    Ok((share, DeviceExchange(state)))
}

fn validate_share(share: &[u8]) -> Result<(), Error> {
    // RFC 9382 P-256 uses uncompressed SEC1. The library validates the point
    // itself, including identity rejection; this enforces the wire profile.
    if share.len() != 65 || share.first() != Some(&4) {
        return Err(Error::InvalidShare);
    }
    Ok(())
}

impl HostExchange {
    pub fn finish(self, peer_share: &[u8]) -> Result<Unconfirmed, Error> {
        validate_share(peer_share)?;
        self.0.finish(peer_share).map(Unconfirmed).map_err(|_| Error::ExchangeFailed)
    }
}

impl DeviceExchange {
    pub fn finish(self, peer_share: &[u8]) -> Result<Unconfirmed, Error> {
        validate_share(peer_share)?;
        self.0.finish(peer_share).map(Unconfirmed).map_err(|_| Error::ExchangeFailed)
    }
}

/// A derived secret is intentionally inaccessible before peer confirmation.
/// Neither this nor the confirmed state implements Clone or Serialize.
pub struct Unconfirmed(Spake2Output);

impl Unconfirmed {
    pub fn confirmation(&self) -> &[u8] {
        &self.0.confirmation_mac
    }

    /// Consumes the exchange even on failure. A retry needs a new admitted
    /// session and a new password. The sender must also send its own tag.
    pub fn verify_peer(self, tag: &[u8]) -> Result<Confirmed, Error> {
        if tag.len() != 32 {
            return Err(Error::ConfirmationFailed);
        }
        self.0.verify_peer_confirmation(tag).map_err(|_| Error::ConfirmationFailed)?;
        Ok(Confirmed(self.0))
    }
}

/// Successful peer confirmation is evidence of the PAKE exchange, not by
/// itself authorization to commit a registry entry. Human confirmation and
/// durable commit/receipt are separate state-machine transitions.
pub struct Confirmed(Spake2Output);

impl Confirmed {
    /// RFC 9382 Ke, 16 bytes in this suite. Use a reviewed application key
    /// schedule with separate labels; do not reuse it directly as a MAC key.
    pub fn key_material(&self) -> &[u8] {
        self.0.session_key.as_bytes()
    }
}

/// Fixed-size application context for native-language bindings. All inputs are
/// obtained independently by the respective endpoint; this is not a wire offer.
impl Context {
    pub const ENCODED_LEN: usize = 219;

    pub fn from_binding_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::ENCODED_LEN { return Err(Error::InvalidContext); }
        let context = Self {
            session_id: bytes[0..16].try_into().map_err(|_| Error::InvalidContext)?,
            host_id: bytes[16..32].try_into().map_err(|_| Error::InvalidContext)?,
            device_id: bytes[32..48].try_into().map_err(|_| Error::InvalidContext)?,
            host_public_key: bytes[48..113].try_into().map_err(|_| Error::InvalidContext)?,
            device_public_key: bytes[113..178].try_into().map_err(|_| Error::InvalidContext)?,
            host_certificate_sha256: bytes[178..210].try_into().map_err(|_| Error::InvalidContext)?,
            expires_at: u64::from_be_bytes(bytes[210..218].try_into().map_err(|_| Error::InvalidContext)?),
            code_entry: match bytes[218] { 0 => CodeEntry::DeviceTypes, 1 => CodeEntry::HostTypes, _ => return Err(Error::InvalidContext) },
        };
        context.aad()?;
        Ok(context)
    }
}

/// Verify the host's tag before releasing the device's confirmation to the
/// transport. The confirmed key never has to leave the native component.
pub fn finish_device(exchange: DeviceExchange, host_share: &[u8], host_tag: &[u8]) -> Result<Vec<u8>, Error> {
    let unconfirmed = exchange.finish(host_share)?;
    let tag = unconfirmed.confirmation().to_vec();
    let _confirmed = unconfirmed.verify_peer(host_tag)?;
    Ok(tag)
}
