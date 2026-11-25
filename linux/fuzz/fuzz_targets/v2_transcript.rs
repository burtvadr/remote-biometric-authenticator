#![no_main]
use libfuzzer_sys::fuzz_target;
use rba_protocol::{v2_message::{self as msg, Domain}, v2_wire as wire};

fuzz_target!(|data: &[u8]| {
    if data.len() > wire::MAX_PAYLOAD + 1 { return; }
    let Some((&selector, payload)) = data.split_first() else { return; };
    let Ok(core) = wire::decode_payload(payload) else { return; };
    let domains = [Domain::AuthRequest, Domain::Matched, Domain::AuthResponse, Domain::EnrollKeyProof, Domain::Policy, Domain::Attest, Domain::EnrollOffer, Domain::EnrollContext];
    let domain = domains[selector as usize % domains.len()];
    if let Ok(transcript) = msg::transcript(domain, &core) {
        let prefix = domain.name().as_bytes();
        assert_eq!(&transcript[..prefix.len()], prefix);
        assert_eq!(transcript[prefix.len()], 0);
        assert_eq!(&transcript[prefix.len()+1..], payload);
        let decoded = wire::decode_payload(&transcript[prefix.len()+1..]).unwrap();
        assert_eq!(msg::hash(domain, &core).unwrap(), msg::hash(domain, &decoded).unwrap());
        for other in domains.into_iter().filter(|d| *d != domain) {
            if let Ok(other_bytes) = msg::transcript(other, &core) {
                assert_ne!(transcript, other_bytes);
            }
        }
    }
});
