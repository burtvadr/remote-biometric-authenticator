//! V2 wire primitives. Not a session or message-schema validator. No V1 fallback.
//! The transport must close on any error and enforce absolute I/O deadlines.
use crate::cbor::Value;
use std::io::{self, Read};

pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 13;
pub const MAX_PAYLOAD: usize = 65_536;
const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 1024;
const MAX_CONTAINER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;
impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid V2 wire data")
    }
}
impl std::error::Error for Invalid {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header { pub message_type: u16, pub payload_len: usize }

fn known(t: u16) -> bool { matches!(t, 10..=24 | 30..=38) }

pub fn parse_header(h: &[u8]) -> Result<Header, Invalid> {
    if h.len() != HEADER_LEN || &h[..4] != b"PAF2" || h[4] != VERSION || h[7..9] != [0, 0] {
        return Err(Invalid);
    }
    let t = u16::from_be_bytes([h[5], h[6]]);
    let n = u32::from_be_bytes([h[9], h[10], h[11], h[12]]);
    if !known(t) || n == 0 || n > MAX_PAYLOAD as u32 { return Err(Invalid); }
    Ok(Header { message_type: t, payload_len: n as usize })
}

/// Only structural wire validation. Message-specific and cryptographic checks
/// (including NFC, label policy, field lengths, signatures and state) are required separately.
pub fn decode_payload(bytes: &[u8]) -> Result<Value, Invalid> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD { return Err(Invalid); }
    let mut d = Decoder { data: bytes, pos: 0, items: 0 };
    let v = d.value(0)?;
    if d.pos != bytes.len() || !matches!(&v, Value::Map(_)) { return Err(Invalid); }
    Ok(v)
}

struct Decoder<'a> { data: &'a [u8], pos: usize, items: usize }
impl<'a> Decoder<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Invalid> {
        let end = self.pos.checked_add(n).ok_or(Invalid)?;
        let b = self.data.get(self.pos..end).ok_or(Invalid)?;
        self.pos = end;
        Ok(b)
    }
    fn arg(&mut self, ai: u8) -> Result<u64, Invalid> {
        let (n, min) = match ai { 0..=23 => return Ok(ai as u64), 24 => (1,24), 25 => (2,256), 26 => (4,65_536), 27 => (8,4_294_967_296), _ => return Err(Invalid) };
        let mut v = 0u64;
        for &b in self.take(n)? { v = (v << 8) | u64::from(b); }
        if v < min { return Err(Invalid); }
        Ok(v)
    }
    fn value(&mut self, depth: usize) -> Result<Value, Invalid> {
        self.items += 1;
        if depth > MAX_DEPTH || self.items > MAX_ITEMS { return Err(Invalid); }
        let h = self.take(1)?[0];
        let major = h >> 5;
        if !matches!(major, 0 | 2 | 3 | 4 | 5) { return Err(Invalid); }
        let a = self.arg(h & 31)?;
        if major == 0 { return Ok(Value::Uint(a)); }
        // Check in u64 before converting to usize (including 32-bit targets).
        if a > MAX_PAYLOAD as u64 { return Err(Invalid); }
        let n = a as usize;
        match major {
            2 => Ok(Value::Bytes(self.take(n)?.to_vec())),
            3 => Ok(Value::Text(std::str::from_utf8(self.take(n)?).map_err(|_| Invalid)?.to_owned())),
            4 | 5 => {
                let width = if major == 4 { 1 } else { 2 };
                if n > MAX_CONTAINER || n * width > self.data.len() - self.pos || n * width > MAX_ITEMS - self.items { return Err(Invalid); }
                if major == 4 {
                    let mut v = Vec::with_capacity(n);
                    for _ in 0..n { v.push(self.value(depth + 1)?); }
                    return Ok(Value::Array(v));
                }
                let mut v = Vec::with_capacity(n);
                let mut prev: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.value(depth + 1)?;
                    if !matches!(&k, Value::Text(_)) { return Err(Invalid); }
                    let raw: &'a [u8] = &self.data[start..self.pos];
                    if prev.is_some_and(|p| p >= raw) { return Err(Invalid); }
                    prev = Some(raw);
                    v.push((k, self.value(depth + 1)?));
                }
                Ok(Value::Map(v))
            }
            _ => Err(Invalid),
        }
    }
}

/// Validates bounds before invoking the existing deterministic encoder.
/// No caller-supplied ordering repair or silent normalization.
pub fn encode_payload(v: &Value) -> Result<Vec<u8>, Invalid> {
    fn head(n: u64) -> usize { match n { 0..=23=>1,24..=255=>2,256..=65535=>3,65536..=4294967295=>5,_=>9 } }
    fn size(v: &Value, depth: usize, items: &mut usize) -> Result<usize, Invalid> {
        *items += 1;
        if depth > MAX_DEPTH || *items > MAX_ITEMS { return Err(Invalid); }
        let n = match v {
            Value::Uint(n) => head(*n),
            Value::Bytes(b) => { if b.len() > MAX_PAYLOAD {return Err(Invalid)}; head(b.len() as u64)+b.len() },
            Value::Text(s) => { if s.len() > MAX_PAYLOAD {return Err(Invalid)}; head(s.len() as u64)+s.len() },
            Value::Array(a) => {
                if a.len() > MAX_CONTAINER { return Err(Invalid); }
                let mut n = head(a.len() as u64);
                for x in a { n += size(x, depth+1, items)?; if n > MAX_PAYLOAD {return Err(Invalid)} }
                n
            }
            Value::Map(m) => {
                if m.len() > MAX_CONTAINER { return Err(Invalid); }
                let mut n = head(m.len() as u64);
                for (k,x) in m {
                    if !matches!(k, Value::Text(_)) { return Err(Invalid); }
                    n += size(k,depth+1,items)? + size(x,depth+1,items)?;
                    if n > MAX_PAYLOAD {return Err(Invalid)}
                }
                n
            }
            _ => return Err(Invalid),
        };
        if n > MAX_PAYLOAD {return Err(Invalid)}
        Ok(n)
    }
    if !matches!(v, Value::Map(_)) { return Err(Invalid); }
    let mut items = 0;
    size(v, 0, &mut items)?;
    let bytes = crate::cbor::encode(v);
    decode_payload(&bytes)?;
    Ok(bytes)
}

pub fn encode_frame(message_type: u16, payload: &Value) -> Result<Vec<u8>, Invalid> {
    if !known(message_type) { return Err(Invalid); }
    let bytes = encode_payload(payload)?;
    let mut out = Vec::with_capacity(HEADER_LEN + bytes.len());
    out.extend_from_slice(b"PAF2"); out.push(VERSION);
    out.extend_from_slice(&message_type.to_be_bytes()); out.extend_from_slice(&[0,0]);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes()); out.extend_from_slice(&bytes);
    Ok(out)
}

/// Reads exactly one frame. Call only on a deadline-bounded authenticated carrier.
/// Never resynchronizes. Unknown message types are rejected before body allocation.
pub fn read_frame(r: &mut impl Read) -> io::Result<(Header, Value)> {
    let bad = |_| io::Error::new(io::ErrorKind::InvalidData, Invalid);
    let mut h = [0; HEADER_LEN]; r.read_exact(&mut h)?;
    let header = parse_header(&h).map_err(bad)?;
    let mut body = vec![0; header.payload_len]; r.read_exact(&mut body)?;
    Ok((header, decode_payload(&body).map_err(bad)?))
}
