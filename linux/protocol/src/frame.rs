//! Protocol framing (`PROTOCOL.md` §4).
//!
//! Framing is deliberately strict: a receiver consumes exactly
//! `13 + payload_len` bytes. There is no resynchronisation scan, because
//! `PAF1` can legitimately occur inside a payload and scanning for it would let
//! an attacker inject a forged frame boundary. A stream that desynchronises is
//! failed closed and the connection is dropped.

use std::io::{self, Read};

use crate::MAX_FRAME_PAYLOAD as MAX_FRAME_PAYLOAD_LIMIT;

pub const MAGIC: [u8; 4] = *b"PAF1";
pub const HEADER_LEN: usize = 13;
/// Mirror of [`crate::MAX_FRAME_PAYLOAD`], re-exported here so framing code
/// needs a single import.
pub const MAX_FRAME_PAYLOAD: usize = MAX_FRAME_PAYLOAD_LIMIT;
pub const PROTOCOL_VERSION: u8 = crate::PROTOCOL_VERSION as u8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub msg_type: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    /// First four bytes were not `PAF1`.
    BadMagic([u8; 4]),
    /// Version byte this implementation does not speak.
    UnsupportedVersion(u8),
    /// Nonzero flags: `PROTOCOL.md` §4 forbids them in v1.
    UnsupportedFlags(u16),
    /// `payload_len` exceeds `MAX_FRAME_PAYLOAD`.
    PayloadTooLarge(u32),
    /// The stream ended before the declared number of bytes arrived.
    Truncated {
        expected: usize,
        got: usize,
    },
    /// Declared length inconsistent with what is actually available.
    BadLength(u32),
}

impl PartialEq for FrameError {
    fn eq(&self, other: &Self) -> bool {
        // I/O errors compare by kind and message rather than by identity, so
        // that assertions in tests remain meaningful.
        match (self, other) {
            (FrameError::Io(a), FrameError::Io(b)) => {
                a.kind() == b.kind() && a.to_string() == b.to_string()
            }
            (FrameError::BadMagic(a), FrameError::BadMagic(b)) => a == b,
            (FrameError::UnsupportedVersion(a), FrameError::UnsupportedVersion(b)) => a == b,
            (FrameError::UnsupportedFlags(a), FrameError::UnsupportedFlags(b)) => a == b,
            (FrameError::PayloadTooLarge(a), FrameError::PayloadTooLarge(b)) => a == b,
            (
                FrameError::Truncated {
                    expected: e1,
                    got: g1,
                },
                FrameError::Truncated {
                    expected: e2,
                    got: g2,
                },
            ) => e1 == e2 && g1 == g2,
            (FrameError::BadLength(a), FrameError::BadLength(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for FrameError {}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "frame io error: {e}"),
            FrameError::BadMagic(m) => write!(f, "frame: bad magic {m:02x?}"),
            FrameError::UnsupportedVersion(v) => write!(f, "frame: unsupported version {v}"),
            FrameError::UnsupportedFlags(f2) => write!(f, "frame: nonzero flags {f2:#06x}"),
            FrameError::PayloadTooLarge(n) => write!(f, "frame: payload too large ({n})"),
            FrameError::Truncated { expected, got } => {
                write!(f, "frame: truncated (expected {expected}, got {got})")
            }
            FrameError::BadLength(n) => write!(f, "frame: bad length field {n}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        FrameError::Io(e)
    }
}

impl Frame {
    pub fn new(msg_type: u16, payload: Vec<u8>) -> Frame {
        Frame {
            version: PROTOCOL_VERSION,
            msg_type,
            flags: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decodes exactly one frame from the front of `buf`, returning the frame
    /// and the number of bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Frame, usize), FrameError> {
        if buf.len() < 4 {
            return Err(FrameError::Truncated {
                expected: 4,
                got: buf.len(),
            });
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[..4]);
        if magic != MAGIC {
            return Err(FrameError::BadMagic(magic));
        }
        if buf.len() < HEADER_LEN {
            return Err(FrameError::Truncated {
                expected: HEADER_LEN,
                got: buf.len(),
            });
        }
        let version = buf[4];
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }
        let msg_type = u16::from_be_bytes([buf[5], buf[6]]);
        let flags = u16::from_be_bytes([buf[7], buf[8]]);
        if flags != 0 {
            return Err(FrameError::UnsupportedFlags(flags));
        }
        let len = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
        if len as usize > MAX_FRAME_PAYLOAD_LIMIT {
            return Err(FrameError::PayloadTooLarge(len));
        }
        let total = HEADER_LEN + len as usize;
        if buf.len() < total {
            return Err(FrameError::Truncated {
                expected: total,
                got: buf.len(),
            });
        }
        Ok((
            Frame {
                version,
                msg_type,
                flags,
                payload: buf[HEADER_LEN..total].to_vec(),
            },
            total,
        ))
    }
}

/// Reads frames from a byte stream with a bounded internal buffer.
pub struct FrameReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
    cap: usize,
}

impl<R: Read> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        FrameReader {
            inner,
            buf: Vec::new(),
            start: 0,
            // HEADER_LEN + MAX_FRAME_PAYLOAD, with slack for the next header.
            cap: HEADER_LEN + MAX_FRAME_PAYLOAD_LIMIT + HEADER_LEN,
        }
    }

    /// Reads the next frame. Returns `Ok(None)` on a clean end of stream.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        loop {
            if let Some((f, n)) = try_decode(&self.buf[self.start..])? {
                self.start += n;
                self.compact();
                return Ok(Some(f));
            }
            // Compact before growing so long-lived connections do not grow
            // without bound.
            self.compact();
            if self.buf.len() > self.cap {
                return Err(FrameError::PayloadTooLarge(self.buf.len() as u32));
            }
            let mut chunk = [0u8; 4096];
            let n = self.inner.read(&mut chunk)?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(FrameError::Truncated {
                    expected: self.buf.len(),
                    got: 0,
                });
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

/// Writes frames to a stream.
pub struct FrameWriter<W: std::io::Write> {
    inner: W,
}

impl<W: std::io::Write> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        FrameWriter { inner }
    }

    pub fn write_frame(&mut self, f: &Frame) -> io::Result<()> {
        self.inner.write_all(&f.encode())?;
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Async framing
// ---------------------------------------------------------------------------
//
// Same strict rules as the synchronous reader, so the daemon and the device
// simulator cannot drift apart in how they parse a frame.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads frames from an async byte stream.
pub struct AsyncFrames<R> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
    cap: usize,
}

impl<R: AsyncRead + Unpin> AsyncFrames<R> {
    pub fn new(inner: R) -> Self {
        AsyncFrames {
            inner,
            buf: Vec::new(),
            start: 0,
            cap: HEADER_LEN + MAX_FRAME_PAYLOAD + HEADER_LEN,
        }
    }

    /// Returns the next frame, or `Ok(None)` at a clean end of stream.
    ///
    /// A stream that ends mid-frame is an error, not a partial frame: the
    /// connection is dropped rather than re-synchronised.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        loop {
            if let Some((f, n)) = try_decode(&self.buf[self.start..])? {
                self.start += n;
                self.compact();
                return Ok(Some(f));
            }
            self.compact();
            if self.buf.len() > self.cap {
                return Err(FrameError::PayloadTooLarge(self.buf.len() as u32));
            }
            let mut chunk = [0u8; 4096];
            let n = self.inner.read(&mut chunk).await.map_err(FrameError::Io)?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(FrameError::Truncated {
                    expected: self.buf.len(),
                    got: 0,
                });
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

fn try_decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    // Validate the fixed header before waiting for a peer-controlled body.
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&buf[..4]);
    if magic != MAGIC {
        return Err(FrameError::BadMagic(magic));
    }
    if buf[4] != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion(buf[4]));
    }
    let flags = u16::from_be_bytes([buf[7], buf[8]]);
    if flags != 0 {
        return Err(FrameError::UnsupportedFlags(flags));
    }
    let len = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    if len as usize > MAX_FRAME_PAYLOAD {
        return Err(FrameError::PayloadTooLarge(len));
    }
    if buf.len() < HEADER_LEN + len as usize {
        return Ok(None);
    }
    let (f, n) = Frame::decode(buf)?;
    Ok(Some((f, n)))
}

/// Writes frames to an async byte stream.
pub struct AsyncFrameWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> AsyncFrameWriter<W> {
    pub fn new(inner: W) -> Self {
        AsyncFrameWriter { inner }
    }

    pub async fn write_frame(&mut self, f: &Frame) -> Result<(), FrameError> {
        self.inner
            .write_all(&f.encode())
            .await
            .map_err(FrameError::Io)?;
        self.inner.flush().await.map_err(FrameError::Io)
    }

    /// Writes pre-encoded frame bytes verbatim, for replay simulation.
    pub async fn write_raw(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        self.inner.write_all(bytes).await.map_err(FrameError::Io)?;
        self.inner.flush().await.map_err(FrameError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let f = Frame::new(12, vec![1, 2, 3]);
        let bytes = f.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 3);
        assert_eq!(&bytes[..4], b"PAF1");
        assert_eq!(bytes[4], PROTOCOL_VERSION);
        let (back, n) = Frame::decode(&bytes).unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(back, f);
    }

    #[test]
    fn empty_payload() {
        let f = Frame::new(20, Vec::new());
        let bytes = f.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        let (back, _) = Frame::decode(&bytes).unwrap();
        assert_eq!(back.payload.len(), 0);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut f = Frame::new(1, vec![]).encode();
        f[0] = b'X';
        assert!(matches!(Frame::decode(&f), Err(FrameError::BadMagic(_))));
    }

    #[test]
    fn rejects_future_version() {
        let mut f = Frame::new(1, vec![]).encode();
        f[4] = 9;
        assert_eq!(Frame::decode(&f), Err(FrameError::UnsupportedVersion(9)));
    }

    #[test]
    fn stream_rejects_unsupported_version_before_payload() {
        let mut bytes = Frame::new(1, vec![0; 8]).encode();
        bytes[4] = PROTOCOL_VERSION + 1;
        bytes.truncate(HEADER_LEN);
        let mut reader = FrameReader::new(&bytes[..]);
        assert_eq!(reader.next_frame(), Err(FrameError::UnsupportedVersion(PROTOCOL_VERSION + 1)));
    }

    #[tokio::test]
    async fn async_stream_rejects_unsupported_version_before_payload() {
        let mut bytes = Frame::new(1, vec![0; 8]).encode();
        bytes[4] = PROTOCOL_VERSION + 1;
        bytes.truncate(HEADER_LEN);
        let mut reader = AsyncFrames::new(std::io::Cursor::new(bytes));
        assert_eq!(reader.next_frame().await, Err(FrameError::UnsupportedVersion(PROTOCOL_VERSION + 1)));
    }

    #[test]
    fn rejects_nonzero_flags() {
        let mut f = Frame::new(1, vec![]).encode();
        f[7] = 1; // high byte of the big-endian u16 flags
        assert_eq!(Frame::decode(&f), Err(FrameError::UnsupportedFlags(256)));
        let mut f2 = Frame::new(1, vec![]).encode();
        f2[8] = 2; // low byte
        assert_eq!(Frame::decode(&f2), Err(FrameError::UnsupportedFlags(2)));
    }

    #[test]
    fn rejects_oversized_payload() {
        let mut f = Frame::new(1, vec![]).encode();
        f[9..13].copy_from_slice(&(MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes());
        assert!(matches!(
            Frame::decode(&f),
            Err(FrameError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn stream_reader_splits_consecutive_frames() {
        let a = Frame::new(1, vec![0xaa; 10]);
        let b = Frame::new(2, vec![0xbb; 300]);
        let mut stream = Vec::new();
        stream.extend_from_slice(&a.encode());
        stream.extend_from_slice(&b.encode());
        let mut r = FrameReader::new(&stream[..]);
        assert_eq!(r.next_frame().unwrap().unwrap(), a);
        assert_eq!(r.next_frame().unwrap().unwrap(), b);
        assert!(r.next_frame().unwrap().is_none());
    }

    #[test]
    fn stream_reader_across_arbitrary_chunk_boundaries() {
        // Split into one byte at a time via a Chunked reader.
        struct Chunked<'a> {
            data: &'a [u8],
            pos: usize,
        }
        impl Read for Chunked<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                buf[0] = self.data[self.pos];
                self.pos += 1;
                Ok(1)
            }
        }
        let f = Frame::new(6, vec![7u8; 500]);
        let bytes = f.encode();
        let mut r = FrameReader::new(Chunked {
            data: &bytes,
            pos: 0,
        });
        assert_eq!(r.next_frame().unwrap().unwrap(), f);
    }

    #[test]
    fn truncated_stream_is_an_error_not_a_partial_frame() {
        let f = Frame::new(1, vec![1, 2, 3, 4]);
        let bytes = f.encode();
        let mut r = FrameReader::new(&bytes[..bytes.len() - 2]);
        assert!(matches!(r.next_frame(), Err(FrameError::Truncated { .. })));
    }

    #[tokio::test]
    async fn async_reader_matches_sync_reader_across_chunk_boundaries() {
        let frames = vec![
            Frame::new(1, vec![]),
            Frame::new(2, vec![7u8; 700]),
            Frame::new(3, MAGIC.to_vec()),
        ];
        let mut bytes = Vec::new();
        for f in &frames {
            bytes.extend_from_slice(&f.encode());
        }
        let mut r = AsyncFrames::new(std::io::Cursor::new(bytes));
        for expected in &frames {
            assert_eq!(r.next_frame().await.unwrap().unwrap(), *expected);
        }
        assert!(r.next_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn async_reader_fails_closed_on_a_truncated_stream() {
        let f = Frame::new(1, vec![1, 2, 3]);
        let mut bytes = f.encode();
        bytes.truncate(bytes.len() - 1);
        let mut r = AsyncFrames::new(std::io::Cursor::new(bytes));
        assert!(matches!(
            r.next_frame().await,
            Err(FrameError::Truncated { .. })
        ));
    }

    #[tokio::test]
    async fn async_writer_and_reader_roundtrip() {
        let f = Frame::new(12, vec![1, 2, 3, 4]);
        let mut w = AsyncFrameWriter::new(Vec::new());
        w.write_frame(&f).await.unwrap();
        let mut buf = std::io::Cursor::new(w.inner);
        let mut r = AsyncFrames::new(&mut buf);
        assert_eq!(r.next_frame().await.unwrap().unwrap(), f);
    }

    #[test]
    fn embedded_magic_in_payload_does_not_resync() {
        // A payload containing "PAF1" must be returned as data, not treated as
        // the start of a new frame.
        let f = Frame::new(1, MAGIC.to_vec());
        let bytes = f.encode();
        let mut r = FrameReader::new(&bytes[..]);
        let got = r.next_frame().unwrap().unwrap();
        assert_eq!(got.payload, MAGIC.to_vec());
        assert!(r.next_frame().unwrap().is_none());
    }
}
