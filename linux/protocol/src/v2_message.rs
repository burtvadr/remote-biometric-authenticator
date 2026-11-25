//! Exact V2 schemas and transcript construction. This layer authenticates no session by itself.
use crate::{cbor::Value, v2_wire as wire};
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use crate::v2_text_profile::label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Hello = 10,
    HelloAck = 11,
    AuthRequest = 12,
    NumberEntry = 13,
    Matched = 14,
    AuthResponse = 15,
    Cancel = 16,
    AuthResult = 17,
    Revoke = 18,
    RevokeReceipt = 19,
    PolicyOffer = 20,
    PolicyDecision = 21,
    PolicyReceipt = 22,
    EnrollStatusResult = 23,
    EnrollStatus = 24,
    EnrollStart = 30,
    EnrollShare = 31,
    EnrollConfirmA = 32,
    EnrollConfirmB = 33,
    EnrollEvidence = 34,
    EnrollOffer = 35,
    EnrollStaged = 36,
    EnrollReceipt = 37,
    EnrollCancel = 38,
}
impl Kind {
    pub fn from_code(code: u16) -> Result<Self, wire::Invalid> {
        match code {
            10 => Ok(Self::Hello),
            11 => Ok(Self::HelloAck),
            12 => Ok(Self::AuthRequest),
            13 => Ok(Self::NumberEntry),
            14 => Ok(Self::Matched),
            15 => Ok(Self::AuthResponse),
            16 => Ok(Self::Cancel),
            17 => Ok(Self::AuthResult),
            18 => Ok(Self::Revoke),
            19 => Ok(Self::RevokeReceipt),
            20 => Ok(Self::PolicyOffer),
            21 => Ok(Self::PolicyDecision),
            22 => Ok(Self::PolicyReceipt),
            23 => Ok(Self::EnrollStatusResult),
            24 => Ok(Self::EnrollStatus),
            30 => Ok(Self::EnrollStart),
            31 => Ok(Self::EnrollShare),
            32 => Ok(Self::EnrollConfirmA),
            33 => Ok(Self::EnrollConfirmB),
            34 => Ok(Self::EnrollEvidence),
            35 => Ok(Self::EnrollOffer),
            36 => Ok(Self::EnrollStaged),
            37 => Ok(Self::EnrollReceipt),
            38 => Ok(Self::EnrollCancel),
            _ => Err(wire::Invalid),
        }
    }
    fn schema(self) -> Schema {
        match self {
            Self::Hello => Schema::Hello,
            Self::HelloAck => Schema::HelloAck,
            Self::AuthRequest => Schema::AuthRequest,
            Self::NumberEntry => Schema::NumberEntry,
            Self::Matched => Schema::Matched,
            Self::AuthResponse => Schema::AuthResponse,
            Self::Cancel => Schema::Cancel,
            Self::AuthResult => Schema::AuthResult,
            Self::Revoke => Schema::Revoke,
            Self::RevokeReceipt => Schema::RevokeReceipt,
            Self::PolicyOffer => Schema::PolicyOffer,
            Self::PolicyDecision => Schema::PolicyDecision,
            Self::PolicyReceipt => Schema::PolicyReceipt,
            Self::EnrollStatusResult => Schema::EnrollStatusResult,
            Self::EnrollStatus => Schema::EnrollStatus,
            Self::EnrollStart => Schema::EnrollStart,
            Self::EnrollShare => Schema::EnrollShare,
            Self::EnrollConfirmA => Schema::EnrollConfirmA,
            Self::EnrollConfirmB => Schema::EnrollConfirmB,
            Self::EnrollEvidence => Schema::EnrollEvidence,
            Self::EnrollOffer => Schema::EnrollOffer,
            Self::EnrollStaged => Schema::EnrollStaged,
            Self::EnrollReceipt => Schema::EnrollReceipt,
            Self::EnrollCancel => Schema::EnrollCancel,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    AuthRequest,
    Matched,
    AuthResponse,
    EnrollKeyProof,
    Policy,
    Attest,
    EnrollOffer,
    EnrollContext,
}
impl Domain {
    pub fn name(self) -> &'static str {
        match self {
            Self::AuthRequest => "RBA-V2-AUTH-REQUEST",
            Self::Matched => "RBA-V2-MATCHED",
            Self::AuthResponse => "RBA-V2-AUTH-RESPONSE",
            Self::EnrollKeyProof => "RBA-V2-ENROLL-KEY-PROOF",
            Self::Policy => "RBA-V2-POLICY",
            Self::Attest => "RBA-V2-ATTEST",
            Self::EnrollOffer => "RBA-V2-ENROLL-OFFER",
            Self::EnrollContext => "RBA-V2-ENROLL-CONTEXT",
        }
    }
    fn schema(self) -> Schema {
        match self {
            Self::AuthRequest => Schema::AuthCore,
            Self::Matched => Schema::MatchCore,
            Self::AuthResponse => Schema::ResponseCore,
            Self::EnrollKeyProof => Schema::ProofCore,
            Self::Policy => Schema::PolicyCore,
            Self::Attest => Schema::AttestCore,
            Self::EnrollOffer => Schema::EnrollOffer,
            Self::EnrollContext => Schema::EnrollContext,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Schema {
    Scope,
    Context,
    Grant,
    AuthCore,
    MatchCore,
    ResponseCore,
    PolicyCore,
    AttestCore,
    ProofCore,
    EnrollContext,
    Hello,
    HelloAck,
    AuthRequest,
    NumberEntry,
    Matched,
    AuthResponse,
    Cancel,
    AuthResult,
    Revoke,
    RevokeReceipt,
    PolicyOffer,
    PolicyDecision,
    PolicyReceipt,
    EnrollStatusResult,
    EnrollStatus,
    EnrollStart,
    EnrollShare,
    EnrollConfirmA,
    EnrollConfirmB,
    EnrollEvidence,
    EnrollOffer,
    EnrollStaged,
    EnrollReceipt,
    EnrollCancel,
}
#[derive(Clone, Copy)]
enum Field { Id, B32, Version, Uint, Bit, SessionPurpose, One, Ident, Label, Detail, Digits, Suite, Point, Sig, Capabilities, Grants, Certs, Tokens, Nested(Schema) }
impl Schema {
    fn fields(self) -> &'static [(&'static str, Field)] {
        use Field::*;
        match self {
            Self::Scope => &[
                ("purpose", Ident),
                ("service", Ident),
                ("operation", Ident),
            ],
            Self::Context => &[
                ("source", Ident),
                ("detail", Detail),
                ("interaction_id", Id),
            ],
            Self::Grant => &[
                ("credential_id", Id),
                ("approver", Id),
                ("target", Id),
                ("scope", Nested(Schema::Scope)),
            ],
            Self::AuthCore => &[
                ("v", Version),
                ("session_id", Id),
                ("request_id", Id),
                ("host_id", Id),
                ("credential_id", Id),
                ("host_nonce", B32),
                ("device_nonce", B32),
                ("channel", B32),
                ("challenge", B32),
                ("approver", Id),
                ("target", Id),
                ("approver_label", Label),
                ("target_label", Label),
                ("scope", Nested(Schema::Scope)),
                ("context", Nested(Schema::Context)),
                ("policy_revision", Uint),
                ("issued_at", Uint),
                ("expires_at", Uint),
            ],
            Self::MatchCore => &[
                ("v", Version),
                ("session_id", Id),
                ("request_id", Id),
                ("channel", B32),
                ("request_hash", B32),
                ("matched", One),
            ],
            Self::ResponseCore => &[
                ("v", Version),
                ("session_id", Id),
                ("request_id", Id),
                ("channel", B32),
                ("request_hash", B32),
                ("match_hash", B32),
                ("credential_id", Id),
                ("decision", One),
            ],
            Self::PolicyCore => &[
                ("revision", Uint),
                ("grants", Grants),
            ],
            Self::AttestCore => &[
                ("v", Version),
                ("enrollment_id", Id),
                ("host_id", Id),
                ("nonce", B32),
                ("channel", B32),
                ("role", Bit),
            ],
            Self::ProofCore => &[
                ("v", Version),
                ("enrollment_id", Id),
                ("host_id", Id),
                ("credential_id", Id),
                ("channel", B32),
                ("nonce", B32),
                ("transport_key", Point),
                ("biometric_key", Point),
                ("role", Bit),
            ],
            Self::EnrollContext => &[
                ("v", Version),
                ("enrollment_id", Id),
                ("host_id", Id),
                ("credential_id", Id),
                ("nonce", B32),
                ("expires_at", Uint),
                ("direction", Bit),
                ("suite", Suite),
                ("channel", B32),
                ("host_cert", B32),
                ("provisional_client_cert", B32),
                ("host_key", Point),
                ("provisional_client_key", Point),
                ("transport_key", Point),
                ("biometric_key", Point),
            ],
            Self::Hello => &[
                ("v", Version),
                ("host_id", Id),
                ("session_id", Id),
                ("host_nonce", B32),
                ("capabilities", Capabilities),
            ],
            Self::HelloAck => &[
                ("v", Version),
                ("host_id", Id),
                ("session_id", Id),
                ("host_nonce", B32),
                ("device_nonce", B32),
                ("credential_id", Id),
                ("purpose", SessionPurpose),
                ("capabilities", Capabilities),
            ],
            Self::AuthRequest => &[
                ("core", Nested(Schema::AuthCore)),
                ("signature", Sig),
            ],
            Self::NumberEntry => &[
                ("session_id", Id),
                ("request_id", Id),
                ("digits", Digits),
            ],
            Self::Matched => &[
                ("core", Nested(Schema::MatchCore)),
                ("signature", Sig),
            ],
            Self::AuthResponse => &[
                ("core", Nested(Schema::ResponseCore)),
                ("signature", Sig),
            ],
            Self::Cancel => &[
                ("session_id", Id),
                ("request_id", Id),
            ],
            Self::AuthResult => &[
                ("session_id", Id),
                ("request_id", Id),
                ("outcome", Bit),
            ],
            Self::Revoke => &[
                ("session_id", Id),
                ("credential_id", Id),
                ("token", B32),
            ],
            Self::RevokeReceipt => &[
                ("session_id", Id),
                ("credential_id", Id),
            ],
            Self::PolicyOffer => &[
                ("session_id", Id),
                ("revision", Uint),
                ("grants", Grants),
                ("digest", B32),
            ],
            Self::PolicyDecision => &[
                ("session_id", Id),
                ("revision", Uint),
                ("digest", B32),
                ("accepted", Bit),
            ],
            Self::PolicyReceipt => &[
                ("session_id", Id),
                ("revision", Uint),
                ("digest", B32),
            ],
            Self::EnrollStatusResult => &[
                ("session_id", Id),
                ("enrollment_id", Id),
                ("state", Bit),
                ("receipt", B32),
            ],
            Self::EnrollStatus => &[
                ("session_id", Id),
                ("enrollment_id", Id),
                ("receipt", B32),
            ],
            Self::EnrollStart => &[
                ("v", Version),
                ("enrollment_id", Id),
                ("host_id", Id),
                ("nonce", B32),
                ("expires_at", Uint),
                ("direction", Bit),
                ("suite", Suite),
            ],
            Self::EnrollShare => &[
                ("enrollment_id", Id),
                ("credential_id", Id),
                ("transport_key", Point),
                ("biometric_key", Point),
                ("share", Point),
            ],
            Self::EnrollConfirmA => &[
                ("enrollment_id", Id),
                ("share", Point),
                ("confirmation", B32),
            ],
            Self::EnrollConfirmB => &[
                ("enrollment_id", Id),
                ("confirmation", B32),
            ],
            Self::EnrollEvidence => &[
                ("enrollment_id", Id),
                ("transport_chain", Certs),
                ("biometric_chain", Certs),
                ("transport_proof", Sig),
                ("biometric_proof", Sig),
                ("cleanup_tokens", Tokens),
            ],
            Self::EnrollOffer => &[
                ("enrollment_id", Id),
                ("credential_id", Id),
                ("grants", Grants),
                ("revision", Uint),
                ("token", B32),
                ("receipt", B32),
            ],
            Self::EnrollStaged => &[
                ("enrollment_id", Id),
                ("offer_hash", B32),
            ],
            Self::EnrollReceipt => &[
                ("enrollment_id", Id),
                ("receipt", B32),
                ("offer_hash", B32),
            ],
            Self::EnrollCancel => &[
                ("enrollment_id", Id),
            ],
        }
    }
}

fn require(ok: bool) -> Result<(), wire::Invalid> { if ok { Ok(()) } else { Err(wire::Invalid) } }
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value, wire::Invalid> { v.get(name).ok_or(wire::Invalid) }
fn bytes(v: &Value) -> Result<&[u8], wire::Invalid> { v.as_bytes().ok_or(wire::Invalid) }
fn text(v: &Value) -> Result<&str, wire::Invalid> { v.as_text().ok_or(wire::Invalid) }
fn uint(v: &Value) -> Result<u64, wire::Invalid> { v.as_uint().ok_or(wire::Invalid) }
fn array(v: &Value) -> Result<&[Value], wire::Invalid> { match v { Value::Array(a) => Ok(a), _ => Err(wire::Invalid) } }
fn ident(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) }
fn validate_field(f: Field, v: &Value) -> Result<(), wire::Invalid> {
    use Field::*;
    match f {
        Id => require(bytes(v)?.len() == 16), B32 => require(bytes(v)?.len() == 32),
        Version => require(uint(v)? == u64::from(wire::VERSION)), Uint => { uint(v)?; Ok(()) },
        Bit => require(uint(v)? <= 1), SessionPurpose => require(uint(v)? <= 3), One => require(uint(v)? == 1),
        Ident => require(ident(text(v)?)), Label => require(label(text(v)?,128)), Detail => require(label(text(v)?,256)),
        Digits => { let s = text(v)?; require(s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit())) },
        Suite => require(text(v)? == "rba-spake2-p256-sha256-v2"),
        Point => { crate::crypto::PublicKey::from_bytes(bytes(v)?).map_err(|_| wire::Invalid)?; Ok(()) },
        Sig => { Signature::from_slice(bytes(v)?).map_err(|_| wire::Invalid)?; Ok(()) },
        Capabilities => {
            let a = array(v)?; let mut previous = "";
            for x in a { let s = text(x)?; require(ident(s) && previous < s)?; previous = s; }
            for s in ["number-match", "attestation", "tls-exporter", "strong-biometric"] { require(a.iter().any(|x| x.as_text() == Some(s)))?; }
            Ok(())
        },
        Grants => {
            let mut previous: Option<Vec<u8>> = None;
            for x in array(v)? {
                validate(Schema::Grant,x)?;
                let enc = wire::encode_payload(x)?;
                require(previous.as_ref().is_none_or(|p| p < &enc))?;
                previous = Some(enc);
            }
            Ok(())
        },
        Certs => { let a = array(v)?; require((1..=8).contains(&a.len()))?; for x in a { require((1..=8192).contains(&bytes(x)?.len()))?; } Ok(()) },
        Tokens => { for x in array(v)? { require(bytes(x)?.len() == 32)?; } Ok(()) },
        Nested(s) => validate(s,v),
    }
}
fn validate(schema: Schema, v: &Value) -> Result<(), wire::Invalid> {
    let Value::Map(entries) = v else { return Err(wire::Invalid) };
    require(entries.len() == schema.fields().len())?;
    for &(name, f) in schema.fields() { validate_field(f,field(v,name)?)?; }
    match schema {
        Schema::Scope => {
            let p = text(field(v,"purpose")?)?; let s = text(field(v,"service")?)?; let o = text(field(v,"operation")?)?;
            require(p == "authenticate" && matches!((s,o), ("rba","authenticate") | ("sudo","service-auth") | ("gdm","session-auth") | ("polkit","action-auth")))?;
        },
        Schema::AuthCore => {
            let i = uint(field(v,"issued_at")?)?; let e = uint(field(v,"expires_at")?)?;
            require(e.checked_sub(i).is_some_and(|d| (1..=60).contains(&d)))?;
        },
        Schema::EnrollShare | Schema::ProofCore | Schema::EnrollContext => {
            require(field(v,"transport_key")? != field(v,"biometric_key")?)?;
            if schema == Schema::EnrollContext {
                require(field(v,"provisional_client_key")? != field(v,"transport_key")? && field(v,"provisional_client_key")? != field(v,"biometric_key")?)?;
            }
        },
        Schema::EnrollStatusResult => {
            let absent = uint(field(v,"state")?)? == 0;
            require(absent == bytes(field(v,"receipt")?)?.iter().all(|b| *b == 0))?;
        },
        Schema::PolicyOffer => {
            let core = Value::map([("revision",field(v,"revision")?.clone()),("grants",field(v,"grants")?.clone())]);
            require(bytes(field(v,"digest")?)? == hash(Domain::Policy,&core)?.as_slice())?;
        },
        Schema::EnrollOffer => {
            require(field(v,"token")? != field(v,"receipt")?)?;
            for grant in array(field(v,"grants")?)? { require(field(grant,"credential_id")? == field(v,"credential_id")?)?; }
        },
        _ => {},
    }
    Ok(())
}

/// Owned immutable validated payload. Callers must still check direction, session state,
/// clock, channel, pins, authorization and attestation before acting on it.
#[derive(Clone)]
pub struct Message { kind: Kind, payload: Value }
impl Message {
    pub fn new(kind: Kind, payload: Value) -> Result<Self, wire::Invalid> {
        wire::encode_payload(&payload)?;
        validate(kind.schema(), &payload)?;
        Ok(Self { kind, payload })
    }
    pub fn kind(&self) -> Kind { self.kind }
    pub fn payload(&self) -> &Value { &self.payload }
    pub fn encode(&self) -> Result<Vec<u8>, wire::Invalid> { wire::encode_frame(self.kind as u16, &self.payload) }
    pub fn read(r: &mut impl std::io::Read) -> std::io::Result<Self> {
        let (h,p) = wire::read_frame(r)?;
        Kind::from_code(h.message_type).and_then(|k| Self::new(k,p)).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,e))
    }
}
/// Domain-specific exact transcript, never a caller-selected free-form domain string.
pub fn transcript(domain: Domain, core: &Value) -> Result<Vec<u8>, wire::Invalid> {
    let encoded = wire::encode_payload(core)?;
    validate(domain.schema(),core)?;
    let mut out = domain.name().as_bytes().to_vec(); out.push(0); out.extend(encoded); Ok(out)
}
pub fn hash(domain: Domain, core: &Value) -> Result<[u8;32], wire::Invalid> {
    Ok(Sha256::digest(transcript(domain,core)?).into())
}
/// Verify an ECDSA signature over the exact transcript, not a pre-hash. Trust
/// in the supplied public key is established separately by the caller.
pub fn verify(domain: Domain, core: &Value, public_key: &[u8], signature: &[u8]) -> Result<(), wire::Invalid> {
    require(matches!(domain,Domain::AuthRequest | Domain::Matched | Domain::AuthResponse | Domain::EnrollKeyProof))?;
    let msg = transcript(domain,core)?;
    let key = crate::crypto::PublicKey::from_bytes(public_key).map_err(|_| wire::Invalid)?;
    key.verify(&msg,signature).map_err(|_| wire::Invalid)
}
