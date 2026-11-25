use rba_protocol::{cbor::Value, v2_wire as wire};
use std::io::{Cursor, ErrorKind};

#[test]
fn independent_wire_fixtures() {
    let fixtures = include_str!("../../../protocol/test-vectors/v2-wire.tsv");
    let mut count = 0;
    for line in fixtures.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split('\t');
        let name = fields.next().unwrap();
        let expected = fields.next().unwrap();
        let raw = hex::decode(fields.next().unwrap()).unwrap();
        let mut input = Cursor::new(&raw);
        let result = wire::read_frame(&mut input);
        match expected {
            "accept" => {
                let (h, payload) = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(wire::encode_frame(h.message_type, &payload).unwrap(), raw, "{name}");
                assert_eq!(input.position(), raw.len() as u64, "{name}");
            }
            "bad-header" => {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidData, "{name}");
                assert_eq!(input.position(), wire::HEADER_LEN as u64, "{name}");
            }
            "reject" => assert!(result.is_err(), "{name}"),
            _ => panic!("unknown fixture mode {expected}"),
        }
        count += 1;
    }
    assert!(count >= 60);
}

#[test]
fn one_frame_does_not_consume_the_next() {
    let v = Value::map([("v", Value::Uint(2))]);
    let a = wire::encode_frame(10, &v).unwrap();
    let b = wire::encode_frame(11, &v).unwrap();
    let mut cursor = Cursor::new([a.clone(), b].concat());
    assert_eq!(wire::read_frame(&mut cursor).unwrap().0.message_type, 10);
    assert_eq!(cursor.position(), a.len() as u64);
    assert_eq!(wire::read_frame(&mut cursor).unwrap().0.message_type, 11);
}

#[test]
fn encoder_rejects_invalid_local_values() {
    let bad = [
        Value::Bool(true),
        Value::map([("x", Value::Nint(0))]),
        Value::map([("x", Value::Bytes(vec![0; 65537]))]),
        Value::map([("x", Value::Array(vec![Value::Uint(0); 33]))]),
        Value::Map(vec![(Value::text("z"), Value::Uint(0)), (Value::text("a"), Value::Uint(0))]),
        Value::Map(vec![(Value::text("x"), Value::Uint(0)), (Value::text("x"), Value::Uint(1))]),
    ];
    for v in bad { assert!(wire::encode_frame(10, &v).is_err()); }
    assert!(wire::encode_frame(25, &Value::Map(vec![])).is_err());
}

#[test]
fn semantic_unsigned_boundaries() {
    let payload = wire::decode_payload(&hex::decode("a161781bffffffffffffffff").unwrap()).unwrap();
    assert_eq!(payload.get("x"), Some(&Value::Uint(u64::MAX)));
    let local = Value::map([("x", Value::Uint(256))]);
    assert_eq!(wire::encode_payload(&local).unwrap(), hex::decode("a16178190100").unwrap());
}
