//! Synthetic certificate fixtures are test-only, not Android hardware evidence.
use super::*;
const NOW: i64 = 1767225600;
const CHALLENGE: Hash = [0x33;32];
const FIXTURES: &str = include_str!("fixtures/chains.tsv");
fn fixture(name:&str)->Vec<u8>{
    let line=FIXTURES.lines().filter_map(|l|l.split_once('\t')).find(|(k,_)|*k==name).expect("known fixture");
    hex::decode(line.1).expect("hex fixture")
}
fn policy()->Policy{Policy{package_name:"io.github.burtvadr.rba".into(),release_signer:[0x44;32],minimum_app_version:10,minimum_os_version:90000,minimum_os_patch:202501,minimum_vendor_patch:20250101,minimum_boot_patch:20250101}}
fn snapshot(json:&[u8])->StatusSnapshot{StatusSnapshot::from_authenticated_response(json,NOW-60,NOW+3600).unwrap()}
fn verifier()->AndroidAttestationVerifier{AndroidAttestationVerifier::new(policy(),&[fixture("root")],snapshot(br#"{"entries":{}}"#)).unwrap()}
fn chain(leaf:&str)->Vec<Vec<u8>>{vec![fixture(leaf),fixture("intermediate"),fixture("root")]}
fn verify(v:&mut AndroidAttestationVerifier,c:&[Vec<u8>],biometric:bool,now:i64)->Result<AttestationValidity>{
    let key:[u8;65]=fixture(if biometric{"bio_key"}else{"transport_key"}).try_into().unwrap();
    v.verify(AttestationRequest{chain:c,expected_key:&key,challenge:CHALLENGE,biometric,now})
}
#[test]
fn valid_roles_and_omitted_root(){
    let mut v=verifier();
    let a=verify(&mut v,&chain("biometric"),true,NOW).unwrap();
    assert_eq!(a.attested_at,NOW); assert_eq!(a.status_checked_at,NOW); assert_eq!(a.status_until,NOW+3600);assert_eq!(a.assurance_until,NOW+30*DAY);
    assert!(verify(&mut v,&chain("transport")[..2],false,NOW).is_ok());
}
#[test]
fn rejects_untrusted_incomplete_or_reordered_chain(){
    let mut v=verifier(); let c=chain("biometric");
    assert!(verify(&mut v,&c[..1],true,NOW).is_err());
    let mut reordered=c.clone(); reordered.swap(1,2);
    assert!(verify(&mut v,&reordered,true,NOW).is_err());
    let mut duplicate=c.clone();duplicate.push(c[2].clone());
    assert!(verify(&mut v,&duplicate,true,NOW).is_err());
    assert!(AndroidAttestationVerifier::new(policy(),&[fixture("intermediate")],snapshot(br#"{"entries":{}}"#)).is_err());
    assert!(AndroidAttestationVerifier::new(policy(),&[],snapshot(br#"{"entries":{}}"#)).is_err());
}
#[test]
fn rejects_leaf_key_or_role_mismatch(){
    let mut v=verifier(); let c=chain("biometric");
    assert!(verify(&mut v,&c,false,NOW).is_err());
    let key=fixture("bio_key").try_into().unwrap();
    assert!(v.verify(AttestationRequest{chain:&c,expected_key:&key,challenge:CHALLENGE,biometric:false,now:NOW}).is_err());
    assert!(v.verify(AttestationRequest{chain:&c,expected_key:&key,challenge:[0x55;32],biometric:true,now:NOW}).is_err());
}
#[test]
fn rejects_bad_hardware_app_boot_and_key_policy(){
    let mut v=verifier();
    for name in ["software","software_key","wrong_challenge","wrong_app","wrong_signer","old_app","unlocked","unverified_boot","stale_patch","missing_vendor","timeout","password","software_auth","wrong_purpose","imported","both_auth","duplicate_tag","unknown_tag","duplicate_hw","trailing","missing_extension","expired"]{
        assert!(verify(&mut v,&chain(name),true,NOW).is_err(),"accepted invalid {name}");
    }
}
#[test]
fn rejects_nonleaf_attestation_and_trailing_certificate_data(){
    let mut v=verifier(); let mut c=chain("biometric");
    c[1]=fixture("intermediate_extension");
    assert!(verify(&mut v,&c,true,NOW).is_err());
    let mut c=chain("biometric"); c[0].push(0);
    assert!(verify(&mut v,&c,true,NOW).is_err());
    let mut c=chain("biometric"); *c[0].last_mut().unwrap() ^= 1;
    assert!(verify(&mut v,&c,true,NOW).is_err());
}
#[test]
fn rejects_revocation_on_every_path_member_and_stale_snapshot(){
    let mut v=verifier();
    for s in ["1","2","a"]{
        let json=serde_json::json!({"entries":{(s):{"status":"REVOKED"}}}).to_string();
        v.status=snapshot(json.as_bytes());
        assert!(verify(&mut v,&chain("biometric")[..2],true,NOW).is_err(),"revoked {s}");
    }
    v.status=snapshot(br#"{"entries":{}}"#);
    assert!(verify(&mut v,&chain("biometric"),true,NOW+3600).is_err());
    assert!(verify(&mut v,&chain("biometric"),true,NOW-61).is_err());
}
#[test]
fn status_parser_is_bounded_and_strict(){
    for malformed in [br#"{}"#.as_slice(),br#"{"entries":[]}"#,br#"{"entries":{},"entries":{}}"#,br#"{"entries":{"1":{"status":"REVOKED"},"1":{"status":"SUSPENDED"}}}"#,br#"{"entries":{"01":{"status":"REVOKED"}}}"#,br#"{"entries":{"A":{"status":"REVOKED"}}}"#,br#"{"entries":{"1":{}}}"#]{
        assert!(StatusSnapshot::from_authenticated_response(malformed,NOW,NOW+DAY).is_err());
    }
    assert!(StatusSnapshot::from_authenticated_response(br#"{"entries":{}}"#,NOW,NOW+DAY+1).is_err());
    assert!(StatusSnapshot::from_authenticated_response(br#"{"entries":{}}"#,NOW,NOW).is_err());
    assert!(StatusSnapshot::from_authenticated_response(br#"{"entries":{}}"#,0,NOW).is_err());
    let mut v=verifier();
    let old=StatusSnapshot::from_authenticated_response(br#"{"entries":{}}"#,NOW-61,NOW+3600).unwrap();
    assert!(v.replace_status(old,NOW).is_err());
}
#[test]
fn invalid_configuration_has_no_fallback(){
    let mut p=policy();p.release_signer=[0;32];
    assert!(AndroidAttestationVerifier::new(p,&[fixture("root")],snapshot(br#"{"entries":{}}"#)).is_err());
    let mut p=policy();p.minimum_boot_patch=20250230;
    assert!(AndroidAttestationVerifier::new(p,&[fixture("root")],snapshot(br#"{"entries":{}}"#)).is_err());
}

fn enrolled_store()->crate::v2_store::Store {
    use crate::v2_store as st;
    use rusqlite::{params,Connection};
    use rba_protocol::{cbor::Value as V,v2_wire};
    let db=Connection::open_in_memory().unwrap();st::configure(&db,true).unwrap();db.execute_batch(st::SCHEMA).unwrap();
    db.execute("INSERT INTO host_meta VALUES(1,?,?)",params![&[99u8;16][..],NOW]).unwrap();
    let mut s=st::Store{db,_lock:None};
    let p=st::Principal{id:[1;16],uid:1000,name:"test".into(),generation:[2;16]};s.add_principal(&p,NOW).unwrap();
    let encode=|name:&str|v2_wire::encode_payload(&V::map([("chain",V::Array(chain(name).into_iter().map(V::Bytes).collect()))])).unwrap();
    let tk=fixture("transport_key").try_into().unwrap();let bk=fixture("bio_key").try_into().unwrap();
    s.commit_enrollment(&st::Enrollment{id:[3;16],credential:[4;16],owner:p.id,transport_key:&tk,biometric_key:&bk,transport_chain:&encode("transport"),biometric_chain:&encode("biometric"),attested_at:NOW,assurance_until:NOW+30*DAY,status_checked_at:NOW,status_until:NOW+3600,token_hash:[5;32],receipt_hash:[6;32],offer_hash:[7;32],initial_cli_grant:true,cleanup_tokens:&[]},NOW).unwrap();s
}
fn later_verifier(json:&[u8],at:i64)->AndroidAttestationVerifier {
    let mut status=StatusSnapshot::from_authenticated_response(json,at,at+3600).unwrap();
    status.deadline=Some(std::time::Instant::now()+std::time::Duration::from_secs(3600));
    AndroidAttestationVerifier::new(policy(),&[fixture("root")],status).unwrap()
}
#[test]
fn stored_chains_refresh_without_extending_key_lifetime(){
    let mut s=enrolled_store();let at=NOW+3601;let mut v=later_verifier(br#"{"entries":{}}"#,at);
    let r=s.revalidate_attestation(&mut v,at).unwrap();assert_eq!(r.refreshed,1);assert_eq!(r.revoked,0);
    let e=s.evidence([4;16]).unwrap().unwrap();assert_eq!(e.attested_at,NOW);assert_eq!(e.assurance_until,NOW+30*DAY);assert_eq!(e.status_checked_at,at);assert_eq!(e.status_until,at+3600);
}
#[test]
fn revocation_invalidates_grants_and_never_resurrects(){
    let mut s=enrolled_store();let at=NOW+1;let mut v=later_verifier(br#"{"entries":{"a":{"status":"REVOKED"}}}"#,at);
    let r=s.revalidate_attestation(&mut v,at).unwrap();assert_eq!(r.revoked,1);assert!(s.evidence([4;16]).unwrap().is_none());
    let key=fixture("transport_key").try_into().unwrap();assert_eq!(s.peer_state(&key,&[4;16],at).unwrap(),crate::v2_store::PeerState::RevocationOnly);
    let grants:i64=s.db.query_row("SELECT count(*) FROM grants",[],|r|r.get(0)).unwrap();assert_eq!(grants,0);
    let mut v=later_verifier(br#"{"entries":{}}"#,at+1);assert_eq!(s.revalidate_attestation(&mut v,at+1).unwrap(),RefreshReport::default());assert!(s.evidence([4;16]).unwrap().is_none());
}
#[test]
fn status_update_rollback_and_authority_suspension(){
    use crate::v2_store as st;
    use std::time::Instant;
    let s=enrolled_store();s.db.execute_batch("CREATE TRIGGER fail_refresh BEFORE INSERT ON audit_outbox WHEN NEW.kind='status-refresh' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    let mut a=st::authority::Authority::new(s);let now=NOW+1;
    assert!(a.install_attestation(later_verifier(br#"{"entries":{}}"#,now),now,Instant::now()).is_err());
    let e=a.store().evidence([4;16]).unwrap().unwrap();assert_eq!(e.status_until,NOW+3600);
    let p=st::Principal{id:[1;16],uid:1000,name:"test".into(),generation:[2;16]};
    assert!(a.begin_pairing([8;16],p.clone(),now,Instant::now()).is_err());
    a.store().db.execute_batch("DROP TRIGGER fail_refresh").unwrap();
    a.install_attestation(later_verifier(br#"{"entries":{}}"#,now+1),now+1,Instant::now()).unwrap();
    assert!(a.begin_pairing([8;16],p,now+1,Instant::now()).is_ok());
}
#[test]
fn expired_assurance_or_new_policy_requires_fresh_enrollment(){
    let mut s=enrolled_store();let now=NOW+30*DAY;
    let mut v=later_verifier(br#"{"entries":{}}"#,now);assert_eq!(s.revalidate_attestation(&mut v,now).unwrap().revoked,1);
    let mut s=enrolled_store();let mut v=later_verifier(br#"{"entries":{}}"#,NOW+1);v.policy.minimum_app_version=11;
    assert_eq!(s.revalidate_attestation(&mut v,NOW+1).unwrap().revoked,1);
}
#[test]
fn install_rejects_old_snapshot_and_expired_monotonic_deadline(){
    use crate::v2_store::authority::Authority;
    use std::time::{Instant,Duration};
    let mut a=Authority::new(enrolled_store());let at=NOW+1;
    a.install_attestation(later_verifier(br#"{"entries":{}}"#,at),at,Instant::now()).unwrap();
    assert!(a.install_attestation(later_verifier(br#"{"entries":{}}"#,at),at,Instant::now()).is_err());
    let mut v=later_verifier(br#"{"entries":{}}"#,at+1);v.status.deadline=Some(Instant::now()-Duration::from_secs(1));
    assert!(a.install_attestation(v,at+1,Instant::now()).is_err());
}

#[test]
fn transport_digest_profile_never_expands_biometric_digest_policy(){
    let mut v=verifier();
    assert!(verify(&mut v,&chain("transport"),false,NOW).is_ok());
    for n in ["transport_sha_only","transport_none_only"] { assert!(verify(&mut v,&chain(n),false,NOW).is_err()); }
    assert!(verify(&mut v,&chain("bio_none"),true,NOW).is_err());
}
