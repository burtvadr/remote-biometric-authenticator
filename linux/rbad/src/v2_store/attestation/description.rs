//! Bounded, strict DER reader for the Android KeyDescription extension only.
//! X.509 certificate parsing and cryptography are delegated to maintained libraries.
use super::{denied, Policy};
use crate::v2_store::{Error, Hash, Result};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
struct Item<'a> { class: u8, constructed: bool, tag: u32, body: &'a [u8] }
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let (&b, rest) = self.0.split_first().ok_or(Error::Invalid)?;
        self.0 = rest; Ok(b)
    }
    fn next(&mut self) -> Result<Item<'a>> {
        let h = self.byte()?;
        let mut tag = u32::from(h & 31);
        if tag == 31 {
            tag = 0;
            let mut count = 0;
            loop {
                let b = self.byte()?;
                if count == 0 && b & 127 == 0 { return Err(Error::Invalid); }
                count += 1;
                if count > 4 { return Err(Error::Invalid); }
                tag = tag.checked_mul(128).and_then(|n| n.checked_add(u32::from(b & 127))).ok_or(Error::Invalid)?;
                if b & 128 == 0 { break; }
            }
            if tag < 31 { return Err(Error::Invalid); }
        }
        let l = self.byte()?;
        let len = if l < 128 { usize::from(l) } else {
            let count = usize::from(l & 127);
            if count == 0 || count > 4 { return Err(Error::Invalid); }
            let mut n = 0usize;
            for i in 0..count {
                let b = self.byte()?;
                if i == 0 && b == 0 { return Err(Error::Invalid); }
                n = n.checked_mul(256).and_then(|n| n.checked_add(usize::from(b))).ok_or(Error::Invalid)?;
            }
            if n < 128 { return Err(Error::Invalid); } n
        };
        let body = self.0.get(..len).ok_or(Error::Invalid)?;
        self.0 = &self.0[len..];
        Ok(Item { class: h >> 6, constructed: h & 32 != 0, tag, body })
    }
    fn end(&self) -> Result<()> { denied(self.0.is_empty()) }
    fn take(&mut self, tag: u32, constructed: bool) -> Result<Item<'a>> {
        let i = self.next()?;
        denied(i.class == 0 && i.tag == tag && i.constructed == constructed)?; Ok(i)
    }
}
impl<'a> Item<'a> {
    fn single(body: &'a [u8]) -> Result<Self> { let mut r = Reader(body); let i = r.next()?; r.end()?; Ok(i) }
    fn is(self, tag: u32, constructed: bool) -> Result<Self> { denied(self.class == 0 && self.tag == tag && self.constructed == constructed)?; Ok(self) }
    fn uint(self, tag: u32) -> Result<u64> {
        let b = self.is(tag, false)?.body;
        denied(!b.is_empty() && b.len() <= 9 && b[0] & 128 == 0 && !(b.len() > 1 && b[0] == 0 && b[1] & 128 == 0))?;
        b.iter().try_fold(0u64, |n, b| n.checked_mul(256).and_then(|n| n.checked_add(u64::from(*b))).ok_or(Error::Invalid))
    }
    fn seq(self) -> Result<Reader<'a>> { Ok(Reader(self.is(16, true)?.body)) }
    fn set(self) -> Result<Reader<'a>> { Ok(Reader(self.is(17, true)?.body)) }
    fn octets(self) -> Result<&'a [u8]> { Ok(self.is(4, false)?.body) }
    fn null(self) -> Result<()> { denied(self.is(5, false)?.body.is_empty()) }
}
type List<'a> = BTreeMap<u32, Item<'a>>;
fn list(i: Item<'_>) -> Result<List<'_>> {
    let mut r = i.seq()?; let mut out = BTreeMap::new(); let mut last = None;
    while !r.0.is_empty() {
        let i = r.next()?;
        denied(i.class == 2 && i.constructed && out.len() < 64 && last.is_none_or(|t| i.tag > t))?;
        last = Some(i.tag);
        out.insert(i.tag, Item::single(i.body)?);
    }
    Ok(out)
}
fn field<'a>(l: &List<'a>, t: u32) -> Result<Item<'a>> { l.get(&t).copied().ok_or(Error::Denied) }
fn number(l: &List<'_>, t: u32, expected: u64) -> Result<()> { denied(field(l,t)?.uint(2)? == expected) }
fn single_number_set(l: &List<'_>, t: u32, expected: u64) -> Result<()> {
    let mut s = field(l,t)?.set()?;
    denied(s.take(2,false)?.uint(2)? == expected)?; s.end()
}
fn application(i: Item<'_>, p: &Policy) -> Result<()> {
    let mut r = Item::single(i.octets()?)?.seq()?;
    let mut packages = r.take(17,true)?.set()?;
    let mut package = packages.take(16,true)?.seq()?;
    denied(package.take(4,false)?.octets()? == p.package_name.as_bytes())?;
    denied(package.take(2,false)?.uint(2)? >= p.minimum_app_version)?;
    package.end()?; packages.end()?;
    let mut digests = r.take(17,true)?.set()?;
    denied(digests.take(4,false)?.octets()? == p.release_signer.as_slice())?;
    digests.end()?; r.end()
}
fn boot(i: Item<'_>) -> Result<()> {
    let mut r = i.seq()?;
    let key = r.take(4,false)?.octets()?;
    denied(matches!(key.len(),32|64) && key.iter().any(|&b| b != 0))?;
    denied(r.take(1,false)?.body == [255])?;
    denied(r.take(10,false)?.uint(10)? == 0)?;
    let hash = r.take(4,false)?.octets()?;
    denied(matches!(hash.len(),32|64) && hash.iter().any(|&b| b != 0))?;
    r.end()
}
// YYYYMM or YYYYMMDD. Reject unknown/zero/impossible dates before comparison.
pub(super) fn patch_date(n: u64, full: bool) -> bool {
    let (ym,d) = if full {(n/100,n%100)} else {(n,1)};
    let (y,m)=(ym/100,ym%100);
    let leap=y%4==0 && (y%100!=0 || y%400==0);
    let max=match m {1|3|5|7|8|10|12=>31,4|6|9|11=>30,2 if leap=>29,2=>28,_=>0};
    (2016..=9999).contains(&y) && (1..=max).contains(&d)
}
fn patch(l: &List<'_>, tag: u32, min: u64, full: bool) -> Result<()> {
    let n=field(l,tag)?.uint(2)?; denied(patch_date(n,full) && n>=min)
}
// Strict signing-key profile. Unknown authorizations are denied until reviewed.
// Allow only known optional metadata; never interpret it as a security guarantee.
fn allowed(l: &List<'_>, hardware: bool) -> Result<()> {
    for (&tag,&i) in l {
        match tag {
            1|2|3|5|10|503|504|702|704|705|706|718|719 if hardware => {},
            709 => { i.octets()?; },
            701 => { i.uint(2)?; }, // creation timestamp, not trusted freshness
            303|703 => { i.null()?; }, // rollback resistance, not relied upon
            724 => { let b=i.octets()?; denied(b.len()==32)?; }, // module hash, not app identity
            _ => return Err(Error::Denied),
        }
    }
    Ok(())
}
/// Recover the original signed challenge from immutable enrolled evidence. This
/// is solely for revalidation; it is not proof of fresh device presence.
pub(super) fn original_challenge(der:&[u8])->Result<Hash>{
    denied(!der.is_empty() && der.len()<=8192)?;
    let mut r=Item::single(der)?.seq()?;
    r.take(2,false)?.uint(2)?; r.take(10,false)?.uint(10)?;
    r.take(2,false)?.uint(2)?; r.take(10,false)?.uint(10)?;
    r.take(4,false)?.octets()?.try_into().map_err(|_|Error::Invalid)
}
pub(super) fn verify_description(der: &[u8], challenge: &Hash, biometric: bool, p: &Policy) -> Result<()> {
    denied(!der.is_empty() && der.len() <= 8192)?;
    let mut r = Item::single(der)?.seq()?;
    let version = r.take(2,false)?.uint(2)?;
    denied(matches!(r.take(10,false)?.uint(10)?,1|2))?;
    let km = r.take(2,false)?.uint(2)?;
    denied(matches!((version,km),(3,4)|(4,41)|(100,100)|(200,200)|(300,300)|(400,400)|(500,500)))?;
    denied(matches!(r.take(10,false)?.uint(10)?,1|2))?;
    denied(r.take(4,false)?.octets()? == challenge.as_slice())?;
    // RBA does not request a persistent unique device identifier.
    denied(r.take(4,false)?.octets()?.is_empty())?;
    let sw=list(r.take(16,true)?)?; let hw=list(r.take(16,true)?)?; r.end()?;
    allowed(&sw,false)?; allowed(&hw,true)?;
    denied(!sw.keys().any(|k| hw.contains_key(k)))?;
    single_number_set(&hw,1,2)?; // sign only
    number(&hw,2,3)?; number(&hw,3,256)?; number(&hw,10,1)?; // EC, P-256
    // Conscrypt's opaque transport-key callback signs an already-hashed TLS
    // CertificateVerify message. Only transport permits NONE + SHA-256.
    if biometric { single_number_set(&hw,5,4)?; }
    else { let mut d=field(&hw,5)?.set()?; denied(d.take(2,false)?.uint(2)?==0)?; denied(d.take(2,false)?.uint(2)?==4)?; d.end()?; }
    number(&hw,702,0)?; // generated in keystore
    if biometric { denied(!hw.contains_key(&503))?; number(&hw,504,2)?; }
    else { denied(!hw.contains_key(&504))?; field(&hw,503)?.null()?; }
    // Timeout, device credential, on-body bypass, application sharing, etc. are
    // rejected by allowed(). Per-operation biometric auth has no timeout tag.
    boot(field(&hw,704)?)?;
    denied(field(&hw,705)?.uint(2)? >= p.minimum_os_version)?;
    patch(&hw,706,p.minimum_os_patch,false)?;
    patch(&hw,718,p.minimum_vendor_patch,true)?;
    patch(&hw,719,p.minimum_boot_patch,true)?;
    application(sw.get(&709).or_else(||hw.get(&709)).copied().ok_or(Error::Denied)?,p)
}
