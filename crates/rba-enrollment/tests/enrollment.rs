use rba_enrollment::{start_device, start_host, CodeEntry, Context, Error, PairingCode, Unconfirmed};

fn public_point(hex_value: &str) -> [u8; 65] {
    hex::decode(hex_value).unwrap().try_into().unwrap()
}

fn context(mode: CodeEntry) -> Context {
    // Public, valid SEC1 points from RFC 9382 Appendix B. These are test data,
    // not credentials, and no deterministic private keys are used in this suite.
    Context {
        session_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        host_public_key: public_point(concat!(
            "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470",
            "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c"
        )),
        device_public_key: public_point(concat!(
            "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676",
            "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7"
        )),
        host_certificate_sha256: [4; 32],
        expires_at: 1_800_000_000,
        code_entry: mode,
    }
}

fn exchange(host: &Context, device: &Context, host_code: &[u8], device_code: &[u8]) -> (Unconfirmed, Unconfirmed) {
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let (ha, hs) = start_host(PairingCode::parse(host_code).unwrap(), host, &mut rng).unwrap();
    let (da, ds) = start_device(PairingCode::parse(device_code).unwrap(), device, &mut rng).unwrap();
    (hs.finish(&da).unwrap(), ds.finish(&ha).unwrap())
}

fn verify_rejected(host: Unconfirmed, device: Unconfirmed) {
    let hm = host.confirmation().to_vec();
    let dm = device.confirmation().to_vec();
    assert!(matches!(host.verify_peer(&dm), Err(Error::ConfirmationFailed)));
    assert!(matches!(device.verify_peer(&hm), Err(Error::ConfirmationFailed)));
}

#[test]
fn both_code_entry_directions_confirm() {
    for mode in [CodeEntry::DeviceTypes, CodeEntry::HostTypes] {
        let c = context(mode);
        let (host, device) = exchange(&c, &c, b"004827", b"004827");
        let hm = host.confirmation().to_vec();
        let dm = device.confirmation().to_vec();
        let h = host.verify_peer(&dm).unwrap();
        let d = device.verify_peer(&hm).unwrap();
        assert_eq!(h.key_material().len(), 16);
        assert_eq!(h.key_material(), d.key_material());
    }
}

#[test]
fn wrong_code_never_confirms() {
    let c = context(CodeEntry::DeviceTypes);
    let (h, d) = exchange(&c, &c, b"004827", b"004828");
    verify_rejected(h, d);
}

#[test]
fn every_context_field_is_bound_to_confirmation() {
    let a = context(CodeEntry::DeviceTypes);
    let mut variants = Vec::new();
    let mut b = a.clone(); b.session_id[0] ^= 1; variants.push(b);
    let mut b = a.clone(); b.host_id[0] ^= 1; variants.push(b);
    let mut b = a.clone(); b.device_id[0] ^= 1; variants.push(b);
    let mut b = a.clone(); b.host_public_key = a.device_public_key; variants.push(b);
    let mut b = a.clone(); b.device_public_key = a.host_public_key; variants.push(b);
    let mut b = a.clone(); b.host_certificate_sha256[0] ^= 1; variants.push(b);
    let mut b = a.clone(); b.expires_at += 1; variants.push(b);
    let mut b = a.clone(); b.code_entry = CodeEntry::HostTypes; variants.push(b);
    for b in variants {
        let (h, d) = exchange(&a, &b, b"004827", b"004827");
        verify_rejected(h, d);
    }
}

#[test]
fn reflected_and_replayed_confirmation_is_rejected() {
    let c = context(CodeEntry::DeviceTypes);
    let (h, d) = exchange(&c, &c, b"004827", b"004827");
    let own = h.confirmation().to_vec();
    let old = d.confirmation().to_vec();
    assert!(matches!(h.verify_peer(&own), Err(Error::ConfirmationFailed)));
    let (fresh, _) = exchange(&c, &c, b"004827", b"004827");
    assert!(matches!(fresh.verify_peer(&old), Err(Error::ConfirmationFailed)));
}

#[test]
fn malformed_inputs_are_rejected() {
    for bad in [b"12345".as_slice(), b"1234567", b"123a56", b" 23456"] {
        assert!(matches!(PairingCode::parse(bad), Err(Error::InvalidCode)));
    }
    let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
    let c = context(CodeEntry::DeviceTypes);
    for bad in [vec![], vec![0], vec![4; 64], vec![2; 65]] {
        let (_, h) = start_host(PairingCode::parse(b"004827").unwrap(), &c, &mut rng).unwrap();
        assert!(matches!(h.finish(&bad), Err(Error::InvalidShare)));
    }
    let (_, h) = start_host(PairingCode::parse(b"004827").unwrap(), &c, &mut rng).unwrap();
    let mut invalid = [0; 65]; invalid[0] = 4;
    assert!(h.finish(&invalid).is_err());
    let (h, _) = exchange(&c, &c, b"004827", b"004827");
    assert!(matches!(h.verify_peer(&[0; 31]), Err(Error::ConfirmationFailed)));
    let mut invalid_context = c;
    invalid_context.device_public_key = [0; 65];
    assert!(matches!(start_host(PairingCode::parse(b"004827").unwrap(), &invalid_context, &mut rng), Err(Error::InvalidContext)));
}

#[test]
fn generated_code_is_six_ascii_digits() {
    let code = PairingCode::generate().unwrap();
    assert!(code.as_ascii().iter().all(u8::is_ascii_digit));
}
