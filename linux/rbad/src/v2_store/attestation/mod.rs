//! Host-side Android Key Attestation verification for V2 enrollment.
//! Only trusted host configuration may supply roots, policy and an authenticated
//! Google status snapshot. There is no system-root or software-key fallback.
//! The runtime must not activate enrollment before the platform adapters are ready.
use super::{authority::{AttestationRequest, AttestationValidity, AttestationVerifier}, Error, Hash, Result};
use openssl::{bn::BigNumContext, ec::PointConversionForm, nid::Nid, stack::Stack,
    x509::{store::X509StoreBuilder, verify::{X509VerifyFlags, X509VerifyParam}, X509StoreContext, X509}};
use serde::{Deserialize, Deserializer, de::{self, MapAccess, Visitor}};
use std::{collections::BTreeSet, fmt};
use x509_parser::parse_x509_certificate;

mod description;
mod provisioning;
mod revalidation;
pub use revalidation::RefreshReport;
#[cfg(test)]
mod tests;
const OID: &str = "1.3.6.1.4.1.11129.2.1.17";
const DAY: i64 = 86400;
const MAX_CERT: usize = 8192;
const MAX_CHAIN: usize = 8;
const MAX_STATUS: usize = 16 * 1024 * 1024;
fn denied(ok: bool) -> Result<()> { if ok { Ok(()) } else { Err(Error::Denied) } }
fn ssl<T>(r: std::result::Result<T, openssl::error::ErrorStack>) -> Result<T> { r.map_err(|_| Error::Denied) }

/// Explicitly provisioned app identity and security floors. No implicit signer.
/// A different signer or package is a different enrollment trust policy.
#[derive(Clone)]
pub struct Policy {
    pub package_name: String,
    pub release_signer: Hash,
    pub minimum_app_version: u64,
    pub minimum_os_version: u64,
    pub minimum_os_patch: u64, // YYYYMM
    pub minimum_vendor_patch: u64, // YYYYMMDD
    pub minimum_boot_patch: u64, // YYYYMMDD
}
impl Policy {
    /// The debug package is deliberately distinct from the release package.
    /// Only the isolated standalone runtime may select this policy. Hardware,
    /// verified boot, key role, patch-date validity and revocation checks stay on.
    pub(crate) fn hardware_test(signer:Hash)->Result<Self>{
        let p=Self{package_name:"io.github.burtvadr.rba.debug".into(),release_signer:signer,
            minimum_app_version:1,minimum_os_version:90000,minimum_os_patch:201808,
            minimum_vendor_patch:20180801,minimum_boot_patch:20180801};
        p.validate()?;Ok(p)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let package_ok=self.package_name == "io.github.burtvadr.rba" ||
            (self.package_name == "io.github.burtvadr.rba.debug" &&
             self.minimum_app_version==1 && self.minimum_os_version==90000 &&
             self.minimum_os_patch==201808 && self.minimum_vendor_patch==20180801 && self.minimum_boot_patch==20180801);
        denied(package_ok && self.release_signer != [0;32]
            && self.minimum_app_version > 0 && self.minimum_os_version >= 90000
            && description::patch_date(self.minimum_os_patch,false)
            && description::patch_date(self.minimum_vendor_patch,true)
            && description::patch_date(self.minimum_boot_patch,true))
    }
}

// Reject duplicate serial keys instead of relying on a JSON map's last-wins
// behavior. All listed serials are denied, including unfamiliar status values.
struct Entries(BTreeSet<String>);
impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self,D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Android attestation status entries") }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> std::result::Result<Entries,M::Error> {
                let mut out = BTreeSet::new();
                while let Some((serial,value)) = m.next_entry::<String,serde_json::Value>()? {
                    if !canonical_serial(&serial) || !value.as_object().and_then(|x|x.get("status")).and_then(|x|x.as_str()).is_some_and(|s|!s.is_empty()) || !out.insert(serial) {
                        return Err(de::Error::custom("invalid or duplicate status entry"));
                    }
                }
                Ok(Entries(out))
            }
        }
        d.deserialize_map(V)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusDocument { entries: Entries }
fn canonical_serial(s:&str)->bool {
    !s.is_empty() && s.len()<=40 && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn serial(bytes:&[u8])->Result<String> {
    // DER serial is signed; RFC 5280 requires a positive value.
    denied(!bytes.is_empty() && bytes.len()<=21 && bytes[0]&128==0)?;
    let h=hex::encode(bytes); let s=h.trim_start_matches('0');
    denied(canonical_serial(s))?; Ok(s.to_owned())
}

/// Parsed from the response of the trusted local HTTPS status fetcher. The
/// fetcher must authenticate the fixed Google URL, bound download size, and
/// supply its real retrieval time and cache deadline. Never from a peer or IPC.
/// Checking a cached response does NOT renew its deadline.
struct StatusSnapshot { entries: BTreeSet<String>, fetched_at: i64, expires_at: i64, deadline: Option<std::time::Instant> }
impl StatusSnapshot {
    fn from_authenticated_response(json:&[u8], fetched_at:i64, expires_at:i64) -> Result<Self> {
        denied(!json.is_empty() && json.len()<=MAX_STATUS && fetched_at>0 && expires_at>fetched_at
            && expires_at.checked_sub(fetched_at).is_some_and(|n|n<=DAY))?;
        let doc: StatusDocument=serde_json::from_slice(json).map_err(|_|Error::Invalid)?;
        Ok(Self{entries:doc.entries.0,fetched_at,expires_at,deadline:None})
    }
    fn fresh(&self, now:i64)->Result<()> { denied(self.fetched_at<=now && now<self.expires_at && self.deadline.is_none_or(|d|std::time::Instant::now()<d)) }
    fn check_serial(&self, bytes:&[u8])->Result<()> { denied(!self.entries.contains(&serial(bytes)?)) }
}

pub struct AndroidAttestationVerifier {
    policy: Policy,
    roots: Vec<X509>,
    status: StatusSnapshot,
}
impl AndroidAttestationVerifier {
    /// Roots must be independently provisioned official Android attestation
    /// anchors. Never call with roots delivered in an enrollment message.
    fn new(policy:Policy, trusted_roots_der:&[Vec<u8>], status:StatusSnapshot)->Result<Self> {
        policy.validate()?;
        denied((1..=8).contains(&trusted_roots_der.len()))?;
        let mut roots=Vec::new(); let mut unique=BTreeSet::new();
        for der in trusted_roots_der {
            let cert=parse_cert(der)?;
            denied(cert.is_ca() && unique.insert(der.clone()))?;
            let root=ssl(X509::from_der(der))?;
            denied(ssl(root.subject_name().to_der())? == ssl(root.issuer_name().to_der())?)?;
            let key=ssl(root.public_key())?;
            denied(ssl(root.verify(&key))?)?;
            roots.push(root);
        }
        Ok(Self{policy,roots,status})
    }
    /// Replacing a snapshot never permits rolling back its retrieval time.
    #[cfg(test)]
    fn replace_status(&mut self, status:StatusSnapshot, now:i64)->Result<()> {
        status.fresh(now)?; denied(status.fetched_at>self.status.fetched_at)?;
        self.status=status; Ok(())
    }
    fn verified_path(&self, supplied:&[Vec<u8>], now:i64)->Result<Vec<Vec<u8>>> {
        self.status.fresh(now)?;
        denied((1..=MAX_CHAIN).contains(&supplied.len()))?;
        let mut unique=BTreeSet::new();
        for der in supplied { parse_cert(der)?; denied(unique.insert(der))?; }
        let leaf=ssl(X509::from_der(&supplied[0]))?;
        let mut intermediate=ssl(Stack::new())?;
        for der in &supplied[1..] { ssl(intermediate.push(ssl(X509::from_der(der))?))?; }
        let mut store=ssl(X509StoreBuilder::new())?;
        // No set_default_paths: trust only the explicit Android roots.
        for root in &self.roots { ssl(store.add_cert(root.clone()))?; }
        let mut param=ssl(X509VerifyParam::new())?;
        param.set_time(now.try_into().map_err(|_|Error::Clock)?);
        param.set_depth(MAX_CHAIN as i32);
        // Require normal validity checking and strict PKIX, not TLS server EKU.
        ssl(param.set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::CHECK_SS_SIGNATURE))?;
        param.set_auth_level(2);
        ssl(store.set_param(&param))?;
        let store=store.build();
        let mut ctx=ssl(X509StoreContext::new())?;
        let path=ssl(ctx.init(&store,&leaf,&intermediate,|ctx| {
            if !ctx.verify_cert()? { return Ok(None); }
            let Some(chain)=ctx.chain() else {return Ok(None)};
            let der:std::result::Result<Vec<_>,_>=chain.iter().map(|c|c.to_der()).collect();
            Ok(Some(der?))
        }))?.ok_or(Error::Denied)?;
        // Require the exact ordered supplied path, permitting an omitted root.
        denied((2..=MAX_CHAIN+1).contains(&path.len()) && (path.len()==supplied.len() || path.len()==supplied.len()+1)
            && path.iter().zip(supplied).all(|(a,b)| a==b))?;
        for der in &path { self.status.check_serial(parse_cert(der)?.raw_serial())?; }
        Ok(path)
    }
}
fn parse_cert(der:&[u8])->Result<x509_parser::certificate::X509Certificate<'_>> {
    denied(!der.is_empty() && der.len()<=MAX_CERT)?;
    let (remaining,cert)=parse_x509_certificate(der).map_err(|_|Error::Invalid)?;
    denied(remaining.is_empty())?;
    let mut unique=BTreeSet::new();
    for ext in cert.extensions() { denied(unique.insert(ext.oid.to_id_string()))?; }
    Ok(cert)
}
impl AttestationVerifier for AndroidAttestationVerifier {
    fn verify(&mut self, r:AttestationRequest<'_>)->Result<AttestationValidity> {
        denied(r.challenge != [0;32] && r.expected_key[0]==4 && p256::PublicKey::from_sec1_bytes(r.expected_key).is_ok())?;
        let path=self.verified_path(r.chain,r.now)?;
        let mut not_after=r.now.checked_add(30*DAY).ok_or(Error::Clock)?;
        for (i,der) in path.iter().enumerate() {
            let cert=parse_cert(der)?;
            not_after=not_after.min(cert.validity().not_after.timestamp());
            let mut extensions=cert.extensions().iter().filter(|e|e.oid.to_id_string()==OID);
            if i!=0 { denied(extensions.next().is_none())?; continue; }
            denied(!cert.is_ca())?;
            // Require digital-signature use, never a CA or CRL signer.
            let usage=cert.key_usage().map_err(|_|Error::Denied)?.ok_or(Error::Denied)?;
            denied(usage.value.digital_signature() && !usage.value.key_cert_sign() && !usage.value.crl_sign())?;
            let leaf=ssl(X509::from_der(der))?;
            let pk=ssl(leaf.public_key())?;
            let ec=ssl(pk.ec_key())?;
            denied(ec.group().curve_name()==Some(Nid::X9_62_PRIME256V1))?;
            let mut bn=ssl(BigNumContext::new())?;
            let point=ssl(ec.public_key().to_bytes(ec.group(),PointConversionForm::UNCOMPRESSED,&mut bn))?;
            denied(point.as_slice()==r.expected_key.as_slice())?;
            let ext=extensions.next().ok_or(Error::Denied)?;
            denied(extensions.next().is_none())?;
            description::verify_description(ext.value,&r.challenge,r.biometric,&self.policy)?;
        }
        denied(not_after>r.now)?;
        // status_checked_at is the actual check time, not retrieval time.
        // Deadline remains anchored to the authenticated snapshot's expiry.
        Ok(AttestationValidity{attested_at:r.now,assurance_until:not_after,status_checked_at:r.now,status_until:self.status.expires_at})
    }
}
