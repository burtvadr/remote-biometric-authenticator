use rba_protocol::{v2_message::{self as msg, Domain, Message}, v2_wire as wire};
use std::io::Cursor;

fn domain(s: &str) -> Domain {
    match s {
        "RBA-V2-AUTH-REQUEST" => Domain::AuthRequest,
        "RBA-V2-MATCHED" => Domain::Matched,
        "RBA-V2-AUTH-RESPONSE" => Domain::AuthResponse,
        "RBA-V2-ENROLL-KEY-PROOF" => Domain::EnrollKeyProof,
        "RBA-V2-POLICY" => Domain::Policy,
        "RBA-V2-ATTEST" => Domain::Attest,
        "RBA-V2-ENROLL-OFFER" => Domain::EnrollOffer,
        "RBA-V2-ENROLL-CONTEXT" => Domain::EnrollContext,
        _ => panic!("unexpected domain {s}"),
    }
}
#[test]
fn independent_message_and_transcript_fixtures() {
    let mut count = 0;
    for line in include_str!("../../../protocol/test-vectors/v2-message.tsv").lines().filter(|l| !l.starts_with('#')) {
        let fields: Vec<_> = line.split('\t').collect();
        let [name, mode, data, extra] = fields.as_slice() else { panic!("invalid fixture") };
        let raw = hex::decode(data).unwrap();
        match *mode {
            "accept" => {
                let mut cursor = Cursor::new(&raw);
                let m = Message::read(&mut cursor).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(m.encode().unwrap(),raw,"{name}");
                assert_eq!(cursor.position(),raw.len() as u64,"{name}");
            },
            "reject" => assert!(Message::read(&mut Cursor::new(&raw)).is_err(),"{name}"),
            "transcript" => {
                let (t,h) = extra.split_once(':').unwrap();
                let core = wire::decode_payload(&raw).unwrap();
                assert_eq!(hex::encode(msg::transcript(domain(name),&core).unwrap()),t,"{name}");
                assert_eq!(hex::encode(msg::hash(domain(name),&core).unwrap()),h,"{name}");
                // Wrong domain must never silently sign an unrelated schema.
                let wrong = if domain(name) == Domain::Attest { Domain::Policy } else { Domain::Attest };
                assert!(msg::transcript(wrong,&core).is_err(),"{name}");
            },
            "verify" | "bad-signature" => {
                let v: Vec<_> = extra.split(':').collect();
                let core = wire::decode_payload(&raw).unwrap();
                let result = msg::verify(domain(v[0]),&core,&hex::decode(v[1]).unwrap(),&hex::decode(v[2]).unwrap());
                assert_eq!(result.is_ok(),*mode == "verify","{name}");
                if *mode == "verify" {
                    // Alter the channel, a valid field of every signed domain.
                    let mut changed = core.clone();
                    if let rba_protocol::cbor::Value::Map(ref mut items) = changed {
                        for (key,value) in items { if key.as_text() == Some("channel") { *value = rba_protocol::cbor::Value::Bytes(vec![99;32]); } }
                    }
                    assert!(msg::verify(domain(v[0]),&changed,&hex::decode(v[1]).unwrap(),&hex::decode(v[2]).unwrap()).is_err(),"{name}: channel tamper");
                }
            },
            _ => panic!("unexpected fixture mode {mode}"),
        }
        count += 1;
    }
    assert!(count >= 250);
}
