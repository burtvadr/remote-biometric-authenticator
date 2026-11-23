//! Bluetooth Low Energy transport adapter.
//!
//! BLE is a *transport*, not a security boundary. The adapter's whole job is to
//! move the same protocol frames that the Wi-Fi transport moves, over GATT
//! characteristics of at most 20 bytes.
//!
//! Two things this module deliberately does **not** do:
//!
//! * Derive identity from the BLE address, the advertised local name, or the
//!   service UUID. Identity is the paired public key, verified by the same
//!   signature check as on Wi-Fi (`PROTOCOL.md` §18).
//! * Weaken anything. A response obtained over BLE verifies identically to one
//!   obtained over TLS, with only the freshness window differing.

use rba_protocol::frame::{Frame, HEADER_LEN};
use rba_protocol::types::Transport;

/// GATT identifiers assigned to this project (`PROTOCOL.md` §13.2).
pub const SERVICE_UUID: &str = rba_protocol::ble::SERVICE_UUID;
/// Host → device characteristic.
pub const RX_CHARACTERISTIC_UUID: &str = rba_protocol::ble::RX_CHARACTERISTIC_UUID;
/// Device → host characteristic.
pub const TX_CHARACTERISTIC_UUID: &str = rba_protocol::ble::TX_CHARACTERISTIC_UUID;

/// Maximum payload in one characteristic value (default GATT MTU 23 − 3).
pub const SEGMENT_SIZE: usize = rba_protocol::ble::SEGMENT_SIZE;

/// Splits an encoded frame into GATT-sized segments.
///
/// The frame bytes are copied verbatim; the adapter never rewrites them. That is
/// what keeps the protocol identical across transports.
pub fn segment(frame: &Frame) -> Vec<Vec<u8>> {
    let bytes = frame.encode();
    if bytes.is_empty() {
        return vec![Vec::new()];
    }
    bytes.chunks(SEGMENT_SIZE).map(|c| c.to_vec()).collect()
}

/// Reassembles segments into a frame.
///
/// Returns `None` while the frame is still incomplete. An inconsistent declared
/// length, or a payload that does not decode as a frame, is an error: on BLE the
/// framing cannot resynchronise, so a malformed stream means the link is broken
/// or tampered with, and the connection must be dropped.
pub fn reassemble(segments: &[Vec<u8>]) -> Option<std::result::Result<Frame, String>> {
    if segments.is_empty() {
        return None;
    }
    let total: usize = segments.iter().map(|s| s.len()).sum();
    if segments[0].len() < HEADER_LEN {
        return None;
    }
    let declared = u32::from_be_bytes([
        segments[0][9],
        segments[0][10],
        segments[0][11],
        segments[0][12],
    ]) as usize;
    if declared > rba_protocol::MAX_FRAME_PAYLOAD {
        return Some(Err(format!(
            "declared payload {declared} exceeds the limit"
        )));
    }
    if total < HEADER_LEN + declared {
        return None;
    }
    if total > HEADER_LEN + declared {
        return Some(Err(format!(
            "received {total} bytes for a {}-byte frame",
            HEADER_LEN + declared
        )));
    }
    let mut buf = Vec::with_capacity(total);
    for s in segments {
        buf.extend_from_slice(s);
    }
    match Frame::decode(&buf) {
        Ok((f, n)) if n == buf.len() => Some(Ok(f)),
        Ok((_, n)) => Some(Err(format!("frame consumed {n} of {} bytes", buf.len()))),
        Err(e) => Some(Err(format!("malformed frame: {e}"))),
    }
}

/// Adapter state for one GATT link.
///
/// Tracks the current reassembly buffer so the caller can feed characteristic
/// notifications and get whole frames back.
#[derive(Debug, Default)]
pub struct Link {
    segments: Vec<Vec<u8>>,
    /// Set once a malformed frame has been seen, so the link can refuse further
    /// input instead of silently resynchronising mid-stream.
    poisoned: bool,
}

impl Link {
    pub fn new() -> Link {
        Link::default()
    }

    /// Feeds one characteristic value. Returns any frames that completed.
    pub fn push(&mut self, segment: &[u8]) -> std::result::Result<Vec<Frame>, String> {
        if self.poisoned {
            return Err("link is poisoned after a malformed frame".into());
        }
        if segment.len() > SEGMENT_SIZE {
            return Err("segment larger than the GATT MTU allows".into());
        }
        self.segments.push(segment.to_vec());
        let snapshot = std::mem::take(&mut self.segments);
        match reassemble(&snapshot) {
            None => {
                self.segments = snapshot;
                Ok(Vec::new())
            }
            Some(Ok(frame)) => Ok(vec![frame]),
            Some(Err(e)) => {
                // Broken link. Clearing the buffer lets a *new* frame start clean
                // after the peer reconnects, while `poisoned` stops this link from
                // being re-synchronised mid-frame.
                self.segments.clear();
                self.poisoned = true;
                Err(e)
            }
        }
    }

    /// Abandons any partially received frame and un-poisons the link, e.g.
    /// after the peer reconnects.
    pub fn reset(&mut self) {
        self.segments.clear();
        self.poisoned = false;
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn pending_segments(&self) -> usize {
        self.segments.len()
    }
}

/// The transport label used in audit records and freshness decisions.
pub const TRANSPORT: Transport = Transport::Ble;

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: usize) -> Frame {
        Frame::new(12, vec![0xAB; payload])
    }

    #[test]
    fn roundtrips_frames_that_fit_in_one_segment() {
        let f = frame(4);
        let segs = segment(&f);
        assert_eq!(segs.len(), 1);
        let back = reassemble(&segs).unwrap().unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn roundtrips_frames_across_many_segments() {
        for size in [0usize, 1, 19, 20, 21, 40, 511, 512, 513, 5000] {
            let f = frame(size);
            let segs = segment(&f);
            let mut link = Link::new();
            let mut out = Vec::new();
            for s in &segs {
                out.extend(link.push(s).unwrap());
            }
            assert_eq!(out.len(), 1, "expected exactly one frame for size {size}");
            assert_eq!(out[0], f, "roundtrip failed for size {size}");
            assert!(segs.iter().all(|s| s.len() <= SEGMENT_SIZE));
        }
    }

    #[test]
    fn link_reports_frames_as_soon_as_they_complete() {
        let f = frame(100);
        let segs = segment(&f);
        let mut link = Link::new();
        let mut frames = Vec::new();
        for s in &segs {
            let got = link.push(s).unwrap();
            frames.extend(got);
            if frames.is_empty() {
                assert!(link.pending_segments() > 0);
            }
        }
        assert_eq!(frames, vec![f]);
    }

    #[test]
    fn consecutive_frames_do_not_bleed_into_each_other() {
        let a = frame(3);
        let b = frame(300);
        let mut link = Link::new();
        let mut got = Vec::new();
        for s in segment(&a).iter().chain(segment(&b).iter()) {
            got.extend(link.push(s).unwrap());
        }
        assert_eq!(got, vec![a, b]);
    }

    #[test]
    fn a_tampered_declared_length_is_rejected_not_accepted() {
        let f = frame(10);
        let mut segs = segment(&f);
        segs[0][9] = 0xff;
        let err = reassemble(&segs).unwrap().unwrap_err();
        assert!(err.contains("exceeds"), "got {err}");
    }

    #[test]
    fn a_link_that_breaks_recovers_for_the_next_frame() {
        let mut link = Link::new();
        // Garbage that decodes as a frame header claiming a huge payload.
        let bad = [0u8; HEADER_LEN];
        assert!(link.push(&bad[..SEGMENT_SIZE.min(HEADER_LEN)]).is_err());
        assert_eq!(link.pending_segments(), 0);
        assert!(link.is_poisoned());
        // A poisoned link refuses everything until it is reset.
        assert!(link.push(&[1, 2, 3]).is_err());
        link.reset();
        assert!(!link.is_poisoned());

        let good = frame(30);
        let mut got = Vec::new();
        for s in segment(&good) {
            got.extend(link.push(&s).unwrap());
        }
        assert_eq!(got, vec![good]);
    }

    #[test]
    fn oversized_segments_are_refused() {
        let mut link = Link::new();
        assert!(link.push(&[0u8; SEGMENT_SIZE + 1]).is_err());
    }

    #[test]
    fn uuids_are_the_project_assigned_ones() {
        assert_eq!(SERVICE_UUID, "8f1c0001-9d2b-4a7e-b0c4-5f6a71c3d801");
        assert_eq!(
            RX_CHARACTERISTIC_UUID,
            "8f1c0002-9d2b-4a7e-b0c4-5f6a71c3d801"
        );
        assert_eq!(
            TX_CHARACTERISTIC_UUID,
            "8f1c0003-9d2b-4a7e-b0c4-5f6a71c3d801"
        );
    }

    #[test]
    fn ble_uses_a_tighter_freshness_window_than_wifi() {
        let (ble_max, ble_window) = Transport::Ble.rate_limit();
        let (wifi_max, wifi_window) = Transport::Wifi.rate_limit();
        assert!(ble_max <= wifi_max);
        assert!(ble_window >= wifi_window);
    }
}
