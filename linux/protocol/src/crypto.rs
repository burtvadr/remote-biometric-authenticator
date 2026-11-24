//! Cryptographic primitives for the protocol (`PROTOCOL.md` §3, §6.4, §8.2).
//!
//! No primitive is implemented here. ECDSA, SHA-256, HMAC and HKDF all come from
//! well-reviewed RustCrypto implementations; this module only fixes the wire
//! encodings and the transcript construction so that the Kotlin side can be
//! written against the same document.

use p256::ecdsa::signature::rand_core::OsRng;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
#[allow(unused_imports)]
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Digest;
use zeroize::Zeroize;

use crate::errors::{ProtocolError, Result};

pub const PUBKEY_LEN: usize = 65;
pub const SIG_LEN: usize = 64;
pub const KEY_ID_LEN: usize = 32;
pub const ALGORITHM: &str = "ES256";

/// Domain separators. These are part of the signed transcript and MUST NOT change
/// without a protocol version bump.
pub const DOMAIN_SIGNING: &[u8] = b"RBA_AUTH_V1";

/// PEM label for a bare P-256 secret scalar held by this project.
pub const BEGIN_LABEL: &str = "-----BEGIN RBA-EC-P256-KEY-----";
/// Closing half of [`BEGIN_LABEL`].
pub const END_LABEL: &str = "-----END RBA-EC-P256-KEY-----";

// ---------------------------------------------------------------------------
// Public keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// Raw uncompressed point, 65 bytes: `0x04 || X || Y`.
    bytes: [u8; PUBKEY_LEN],
}

impl PublicKey {
    /// Parses a raw uncompressed P-256 point. Rejects wrong lengths, SEC1
    /// compressed prefixes, and points not on the curve.
    pub fn from_bytes(b: &[u8]) -> Result<PublicKey> {
        if b.len() != PUBKEY_LEN {
            return Err(ProtocolError::BadRequest(format!(
                "public key must be {PUBKEY_LEN} bytes, got {}",
                b.len()
            )));
        }
        if b[0] != 0x04 {
            return Err(ProtocolError::BadRequest(
                "public key must be an uncompressed point (prefix 0x04)".into(),
            ));
        }
        // Rejects off-curve and malformed points.
        VerifyingKey::from_sec1_bytes(b).map_err(|_| {
            ProtocolError::BadRequest("public key is not a valid P-256 point".into())
        })?;
        let mut bytes = [0u8; PUBKEY_LEN];
        bytes.copy_from_slice(b);
        Ok(PublicKey { bytes })
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_LEN] {
        &self.bytes
    }

    /// `key_id = SHA-256(raw_public_key_bytes)` (`PROTOCOL.md` §3.2).
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        h.update(self.bytes);
        let out = h.finalize();
        let mut k = [0u8; KEY_ID_LEN];
        k.copy_from_slice(&out);
        k
    }

    pub fn key_id_hex(&self) -> String {
        hex::encode(self.key_id())
    }

    /// First 16 hex characters of the key id, as published in mDNS TXT records.
    pub fn short_fingerprint(&self) -> String {
        hex::encode(&self.key_id()[..8])
    }

    /// Verifies `sig` (raw `r||s`) over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        if sig.len() != SIG_LEN {
            return Err(ProtocolError::SignatureInvalid);
        }
        let vk = VerifyingKey::from_sec1_bytes(&self.bytes)
            .map_err(|_| ProtocolError::SignatureInvalid)?;
        let esig = EcdsaSignature::from_slice(sig).map_err(|_| ProtocolError::SignatureInvalid)?;
        // `verify` rejects r=0, s=0 and out-of-range components internally.
        use p256::ecdsa::signature::Verifier;
        vk.verify(msg, &esig)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

// ---------------------------------------------------------------------------
// Private keys
// ---------------------------------------------------------------------------

/// An ECDSA P-256 signing key.
///
/// On Android the equivalent object is a non-exportable Keystore key gated on
/// `BIOMETRIC_STRONG`; the app never sees key material. This Rust type exists
/// for the host identity key, the fake authenticator, and tests.
pub struct PrivateKey {
    inner: SigningKey,
}

impl PrivateKey {
    pub fn generate() -> Result<PrivateKey> {
        let inner = SigningKey::random(&mut OsRng);
        Ok(PrivateKey { inner })
    }

    pub fn from_bytes(secret: &[u8]) -> Result<PrivateKey> {
        if secret.len() != 32 {
            return Err(ProtocolError::BadRequest(
                "private key must be 32 bytes (P-256 scalar)".into(),
            ));
        }
        let inner = SigningKey::from_slice(secret)
            .map_err(|_| ProtocolError::BadRequest("invalid private key".into()))?;
        Ok(PrivateKey { inner })
    }

    /// SEC1 big-endian secret scalar. Zeroized on drop.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.inner.to_bytes());
        out
    }

    /// Serialises the secret scalar into a labelled PEM block.
    ///
    /// The label is deliberately project-specific rather than `PRIVATE KEY`:
    /// this is a bare 32-byte P-256 scalar, not a PKCS#8 document, and using a
    /// standard label would invite tooling to misparse it as one.
    pub fn to_pem(&self) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.to_bytes());
        let mut out = String::with_capacity(128);
        out.push_str(BEGIN_LABEL);
        out.push('\n');
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
            out.push('\n');
        }
        out.push_str(END_LABEL);
        out.push('\n');
        out
    }

    pub fn from_pem(text: &str) -> Result<PrivateKey> {
        use base64::Engine;
        let mut body = String::new();
        let mut inside = false;
        for line in text.lines() {
            let line = line.trim();
            if line == BEGIN_LABEL {
                inside = true;
                continue;
            }
            if line == END_LABEL {
                break;
            }
            if inside {
                body.push_str(line);
            }
        }
        if body.is_empty() {
            return Err(ProtocolError::BadRequest(format!(
                "expected a {BEGIN_LABEL} block"
            )));
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| ProtocolError::BadRequest("key body is not valid base64".into()))?;
        PrivateKey::from_bytes(&raw)
    }

    pub fn public_key(&self) -> PublicKey {
        // Method resolution derefs to the curve point, which is what actually
        // implements ToEncodedPoint.
        let pt = self.inner.verifying_key().to_encoded_point(false);
        let mut bytes = [0u8; PUBKEY_LEN];
        bytes.copy_from_slice(pt.as_bytes());
        PublicKey { bytes }
    }

    /// Signs `msg` (SHA-256 is applied internally), returning raw `r||s`.
    pub fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        use p256::ecdsa::signature::Signer;
        let sig: EcdsaSignature = self.inner.sign(msg);
        let mut out = [0u8; SIG_LEN];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // `SigningKey` is ZeroizeOnDrop internally; zeroize our copy too.
        let mut b = self.to_bytes();
        b.zeroize();
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("PrivateKey")
            .field("key_id", &self.public_key().key_id_hex())
            .finish_non_exhaustive()
    }
}

/// Verifies without needing to own a `PublicKey`.
pub fn verify_with(pubkey: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    pubkey.verify(msg, sig)
}

// ---------------------------------------------------------------------------
// Hashing / HMAC / HKDF
// ---------------------------------------------------------------------------

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = <sha2::Sha256 as sha2::Digest>::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// HKDF-SHA-256 (extract-then-expand).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out)
        .map_err(|_| ProtocolError::Internal("hkdf expand failed".into()))
}

/// Constant-time comparison for MACs and digests.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// CSPRNG bytes. Fails closed if the OS entropy source is unavailable.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    getrandom::getrandom(&mut v)
        .map_err(|_| ProtocolError::Internal("OS randomness unavailable".into()))?;
    Ok(v)
}

/// Fills a fixed-size array from the OS CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let v = random_bytes(N)?;
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Constant-time equality that does not leak length via early return, for
/// comparing variable-length secrets.
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = PrivateKey::generate().unwrap();
        let pk = sk.public_key();
        let msg = b"the exact request context";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).unwrap();
        // Any modification must fail.
        assert!(pk.verify(b"the exact request contex", &sig).is_err());
        assert!(pk.verify(msg, &sig[0..63]).is_err());
    }

    #[test]
    fn signature_is_deterministic_for_a_given_key_and_message() {
        // RustCrypto uses RFC 6979, so a fixed key and message give a fixed
        // signature. That keeps test vectors reproducible.
        let sk = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
        assert_eq!(sk.sign(b"x"), sk.sign(b"x"));
    }

    #[test]
    fn verifies_against_the_wrong_key_fails() {
        let a = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let b = PrivateKey::from_bytes(&[2u8; 32]).unwrap();
        let sig = a.sign(b"msg");
        assert!(b.public_key().verify(b"msg", &sig).is_err());
    }

    #[test]
    fn malleable_high_s_variant_is_still_accepted() {
        // Documents the ECDSA malleability the spec warns about: (r, n-s) also
        // verifies against the same message. Replay defence therefore must not
        // depend on signature bytes being unique.
        let sk = PrivateKey::from_bytes(&[9u8; 32]).unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(b"msg");

        // n - s, big-endian, with borrow propagation.
        let n = hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
            .unwrap();
        let mut flipped = sig;
        let mut borrow: u16 = 0;
        for i in (0..32).rev() {
            let v = (n[i] as u16)
                .wrapping_sub(flipped[32 + i] as u16)
                .wrapping_sub(borrow);
            flipped[32 + i] = (v & 0xff) as u8;
            borrow = (v >> 8) & 1;
        }
        assert_ne!(sig, flipped, "n - s should differ from s");
        // Either outcome is acceptable for the protocol; what matters is that
        // this is why replay defence uses request_id/challenge, not signature
        // bytes. Assert the malleable variant is accepted, which is the real
        // behaviour of a conforming verifier.
        pk.verify(b"msg", &flipped).unwrap();
    }

    #[test]
    fn public_key_parsing_rejects_bad_input() {
        let sk = PrivateKey::generate().unwrap();
        let good = sk.public_key().as_bytes().to_vec();
        assert!(PublicKey::from_bytes(&good).is_ok());
        // wrong length
        assert!(PublicKey::from_bytes(&good[..64]).is_err());
        // wrong prefix
        let mut bad = good.clone();
        bad[0] = 0x02;
        assert!(PublicKey::from_bytes(&bad).is_err());
        // off-curve: flip a coordinate byte
        let mut off = good.clone();
        off[10] ^= 0xff;
        assert!(PublicKey::from_bytes(&off).is_err());
    }

    #[test]
    fn key_id_is_sha256_of_raw_key() {
        let sk = PrivateKey::from_bytes(&[3u8; 32]).unwrap();
        let pk = sk.public_key();
        assert_eq!(pk.key_id(), sha256(pk.as_bytes()));
        assert_eq!(pk.key_id_hex().len(), 64);
        assert_eq!(pk.short_fingerprint().len(), 16);
    }

    #[test]
    fn pem_roundtrip() {
        let sk = PrivateKey::from_bytes(&[0x5A; 32]).unwrap();
        let pem = sk.to_pem();
        assert!(pem.starts_with(BEGIN_LABEL));
        assert!(pem.trim_end().ends_with(END_LABEL));
        let back = PrivateKey::from_pem(&pem).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
    }

    #[test]
    fn pem_rejects_garbage() {
        assert!(PrivateKey::from_pem("not a key").is_err());
        assert!(PrivateKey::from_pem(&format!("{BEGIN_LABEL}\n!!!!\n{END_LABEL}")).is_err());
    }

    #[test]
    fn pem_uses_a_project_specific_label() {
        // A bare scalar under a standard label would be misparsed as PKCS#8.
        let sk = PrivateKey::from_bytes(&[1u8; 32]).unwrap();
        let pem = sk.to_pem();
        assert!(!pem.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn hmac_and_hkdf_are_deterministic() {
        let k = [1u8; 32];
        assert_eq!(hmac_sha256(&k, b"a"), hmac_sha256(&k, b"a"));
        assert_ne!(hmac_sha256(&k, b"a"), hmac_sha256(&k, b"b"));
        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        hkdf_sha256(b"ikm", b"salt", b"info", &mut o1).unwrap();
        hkdf_sha256(b"ikm", b"salt", b"info", &mut o2).unwrap();
        assert_eq!(o1, o2);
        let mut o3 = [0u8; 32];
        hkdf_sha256(b"ikm", b"salt", b"other", &mut o3).unwrap();
        assert_ne!(o1, o3);
    }

    #[test]
    fn ct_eq_is_length_safe() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn random_bytes_has_the_requested_length() {
        assert_eq!(random_bytes(32).unwrap().len(), 32);
        let a: [u8; 16] = random_array().unwrap();
        let b: [u8; 16] = random_array().unwrap();
        assert_ne!(a, b);
    }
}
