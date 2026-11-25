#![no_main]
use libfuzzer_sys::fuzz_target;
use rba_protocol::{v2_message::{Kind, Message}, v2_wire as wire};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > wire::MAX_PAYLOAD + 1 { return; }
    let Some((&selector, payload)) = data.split_first() else { return; };
    let Ok(value) = wire::decode_payload(payload) else { return; };
    assert_eq!(wire::encode_payload(&value).unwrap(), payload);
    let codes: [u16; 24] = [10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,30,31,32,33,34,35,36,37,38];
    let kind = Kind::from_code(codes[selector as usize % codes.len()]).unwrap();
    if let Ok(message) = Message::new(kind, value) {
        let frame = message.encode().unwrap();
        let mut cursor = Cursor::new(frame.as_slice());
        let decoded = Message::read(&mut cursor).unwrap();
        assert_eq!(decoded.kind(), kind);
        assert_eq!(decoded.encode().unwrap(), frame);
        assert_eq!(cursor.position() as usize, frame.len());
        assert_eq!(&frame[wire::HEADER_LEN..], payload);
    }
});
