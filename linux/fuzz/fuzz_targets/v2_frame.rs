#![no_main]
use libfuzzer_sys::fuzz_target;
use rba_protocol::{v2_message::Message, v2_wire as wire};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > wire::HEADER_LEN + wire::MAX_PAYLOAD { return; }
    let mut structural = Cursor::new(data);
    if let Ok((header, value)) = wire::read_frame(&mut structural) {
        let used = structural.position() as usize;
        assert_eq!(used, wire::HEADER_LEN + header.payload_len);
        assert_eq!(wire::encode_frame(header.message_type, &value).unwrap(), data[..used]);
    }
    let mut typed = Cursor::new(data);
    if let Ok(message) = Message::read(&mut typed) {
        let used = typed.position() as usize;
        assert_eq!(message.encode().unwrap(), data[..used]);
        assert_eq!(structural.position(), typed.position());
        assert_eq!(wire::parse_header(&data[..wire::HEADER_LEN]).unwrap().message_type, message.kind() as u16);
    }
});
