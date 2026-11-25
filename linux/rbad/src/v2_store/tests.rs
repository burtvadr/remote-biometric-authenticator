use super::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;

const NOW:i64=1000;
fn id(n:u8)->Id { [n;16] }
fn key(n:u8)->[u8;65] {
    let mut b=[0;32]; b[31]=n;
    p256::SecretKey::from_slice(&b).unwrap().public_key().to_encoded_point(false).as_bytes().try_into().unwrap()
}
fn principal(n:u8,uid:u32)->Principal { Principal{id:id(n),uid,name:format!("user{uid}"),generation:id(n+64)} }
fn create(db:Connection)->Store {
    configure(&db,true).unwrap();
    db.execute_batch(SCHEMA).unwrap();
    db.execute("INSERT INTO host_meta VALUES(1,?,?)",params![&id(99)[..],NOW]).unwrap();
    validate_db(&db,&id(99)).unwrap();
    Store{db,_lock:None}
}
fn enroll(s:&mut Store,n:u8,owner:u8,transport:&[u8;65],bio:&[u8;65],cleanup:&[Hash])->Result<()> {
    enroll_at(s,n,owner,transport,bio,cleanup,NOW)
}
fn enroll_at(s:&mut Store,n:u8,owner:u8,transport:&[u8;65],bio:&[u8;65],cleanup:&[Hash],now:i64)->Result<()> {
    // Dummy chains are storage-test inputs, not trusted attestation.
    s.commit_enrollment(&Enrollment{id:id(n+20),credential:id(n),owner:id(owner),transport_key:transport,biometric_key:bio,transport_chain:b"test-chain",biometric_chain:b"test-chain",attested_at:now,assurance_until:now+100000,status_checked_at:now,status_until:now+86400,token_hash:digest(&[n;32]),receipt_hash:digest(&[n+1;32]),offer_hash:[n+2;32],initial_cli_grant:true,cleanup_tokens:cleanup},now)
}
fn ready()->Store {
    let mut s=create(Connection::open_in_memory().unwrap());
    s.add_principal(&principal(1,1000),NOW).unwrap();
    enroll(&mut s,10,1,&key(1),&key(2),&[]).unwrap(); s
}
fn cli()->Grant { Grant{approver:id(1),target:id(1),scope:Scope::Cli} }
#[test]
fn enrollment_receipt_recovery_and_exact_peer() {
    let s=ready();
    assert_eq!(s.enrollment_status(id(30),id(10),&key(1),&[11;32],NOW).unwrap(),Some([12;32]));
    assert_eq!(s.enrollment_status(id(30),id(10),&key(2),&[11;32],NOW).unwrap(),None);
    assert_eq!(s.enrollment_status(id(30),id(10),&key(1),&[9;32],NOW).unwrap(),None);
    assert_eq!(s.policy(id(10)).unwrap().1,vec![cli()]);
}
#[test]
fn replacement_is_atomic_and_cross_role_reuse_fails() {
    let mut s=ready();
    assert!(enroll(&mut s,11,1,&key(2),&key(3),&[digest(&[10;32])]).is_err());
    assert_eq!(s.peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::Active);
    assert_eq!(s.policy(id(10)).unwrap().1,vec![cli()]);
    enroll(&mut s,11,1,&key(3),&key(4),&[digest(&[10;32])]).unwrap();
    assert_eq!(s.peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::RevocationOnly);
    assert_eq!(s.peer_state(&key(3),&id(11),NOW).unwrap(),PeerState::Active);
}
#[test]
fn principal_reuse_does_not_inherit_credentials() {
    let mut s=ready();
    s.disable_principal(id(1),NOW-1).unwrap(); // administrative revoke works on clock rollback
    let p=principal(2,1000); s.add_principal(&p,NOW).unwrap();
    assert!(!s.principal_matches(&principal(1,1000)).unwrap());
    assert!(s.principal_matches(&p).unwrap());
    assert!(s.reserve_prompt(id(10),cli(),1,NOW).is_err());
    assert_eq!(s.peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::RevocationOnly);
}
#[test]
fn policy_consent_and_revision_are_exact() {
    let mut s=ready();
    let g=Grant{scope:Scope::SudoService,..cli()};
    assert!(s.replace_policy(id(10),1,&[cli(),g],None,NOW).is_err());
    let d=policy_digest(&id(10),2,&[cli(),g]).unwrap();
    s.replace_policy(id(10),1,&[cli(),g],Some(d),NOW).unwrap();
    assert!(s.reserve_prompt(id(10),cli(),1,NOW).is_err());
    assert_eq!(s.reserve_prompt(id(10),g,2,NOW).unwrap(),Reservation::Granted);
    assert_eq!(s.reserve_prompt(id(10),g,2,NOW).unwrap(),Reservation::Exhausted);
    s.replace_policy(id(10),2,&[cli()],None,NOW).unwrap();
    assert!(s.reserve_prompt(id(10),g,3,NOW).is_err());
    assert!(s.replace_policy(id(10),2,&[],None,NOW).is_err());
}
#[test]
fn durable_budgets_are_independent_and_rolling() {
    let mut s=ready();
    for _ in 0..3 { assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW).unwrap(),Reservation::Granted); }
    assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW+59).unwrap(),Reservation::Exhausted);
    assert!(matches!(s.reserve_pairing(id(1),NOW),Err(Error::Clock)));
    for _ in 0..5 { assert_eq!(s.reserve_pairing(id(1),NOW+60).unwrap(),Reservation::Granted); }
    assert_eq!(s.reserve_pairing(id(1),NOW+60).unwrap(),Reservation::Exhausted);
    assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW+60).unwrap(),Reservation::Granted);
    assert_eq!(s.reserve_pairing(id(1),NOW+360).unwrap(),Reservation::Granted);
}
#[test]
fn revoked_retry_expires_and_never_recovers_receipt() {
    let mut s=ready();
    assert!(s.revoke_with_token(id(10),&key(2),&[10;32],NOW).is_err());
    assert!(s.revoke_with_token(id(10),&key(1),&[9;32],NOW).is_err());
    s.revoke_with_token(id(10),&key(1),&[10;32],NOW).unwrap();
    s.revoke_with_token(id(10),&key(1),&[10;32],NOW+1).unwrap();
    assert_eq!(s.enrollment_status(id(30),id(10),&key(1),&[11;32],NOW+1).unwrap(),None);
    assert_eq!(s.peer_state(&key(1),&id(10),NOW+RETRY).unwrap(),PeerState::Unknown);
    assert_eq!(s.cleanup_tombstones(NOW+RETRY).unwrap(),1);
    assert!(s.revoke_with_token(id(10),&key(1),&[10;32],NOW+RETRY).is_err());
}
#[test]
fn status_refresh_cannot_extend_key_lifetime() {
    let mut s=ready();
    assert!(s.refresh_status(id(10),NOW,NOW+86401,NOW).is_err());
    s.refresh_status(id(10),NOW+50000,NOW+130000,NOW+50000).unwrap();
    assert_eq!(s.peer_state(&key(1),&id(10),NOW+99999).unwrap(),PeerState::Active);
    assert_eq!(s.peer_state(&key(1),&id(10),NOW+100000).unwrap(),PeerState::Unknown);
}
#[test]
fn schema_tamper_and_wrong_host_rejected() {
    let s=ready();
    assert!(validate_db(&s.db,&id(98)).is_err());
    s.db.execute_batch("DROP TRIGGER grant_cap").unwrap();
    assert!(validate_db(&s.db,&id(99)).is_err());
}
#[test]
fn audit_is_atomic_with_mutation() {
    let mut s=ready();
    s.db.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON audit_outbox BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(s.revoke(id(10),NOW).is_err());
    assert_eq!(s.peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::Active);
    assert_eq!(s.policy(id(10)).unwrap().1,vec![cli()]);
}

#[test]
fn durable_reservation_survives_reopen() {
    // Test-only direct SQLite path. Production open enforces root ownership and flock.
    let mut random=[0;16]; getrandom::getrandom(&mut random).unwrap();
    let dir=std::env::temp_dir().join(format!("rba-v2-store-{}",hex::encode(random)));
    fs::create_dir(&dir).unwrap();
    let path=dir.join("state.sqlite3");
    {
        let mut s=create(Connection::open(&path).unwrap());
        s.add_principal(&principal(1,1000),NOW).unwrap();
        enroll(&mut s,10,1,&key(1),&key(2),&[]).unwrap();
        for _ in 0..3 { assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW).unwrap(),Reservation::Granted); }
    }
    {
        let db=Connection::open(&path).unwrap(); configure(&db,false).unwrap(); validate_db(&db,&id(99)).unwrap();
        let mut s=Store{db,_lock:None};
        assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW+1).unwrap(),Reservation::Exhausted);
        assert!(matches!(s.reserve_prompt(id(10),cli(),1,NOW),Err(Error::Clock)));
        assert_eq!(s.reserve_prompt(id(10),cli(),1,NOW+60).unwrap(),Reservation::Granted);
    }
    fs::remove_dir_all(dir).unwrap();
}

// B.2.3: test trusted-adapter facts only in the harness. These fixtures do not
// establish real IPC provenance, TLS, attestation or biometric verification.
mod authorization {
    use super::*;
    use super::super::authority::{Authority,Carrier,ConnectionId,Listener,LocalIntent,Origin,Peer};
    use std::{net::IpAddr,time::Instant};
    fn intent(owner:u8)->LocalIntent {
        let p=principal(1,1000);
        LocalIntent{owner:id(owner),interaction:id(owner+1),caller:p.clone(),approver:p.clone(),target:p,scope:Scope::Cli,origin:Origin::SelfCli{peer_uid:1000}}
    }
    fn peer(a:&mut Authority, n:u8, mono:Instant, now:i64)->ConnectionId {
        let c=a.connect(IpAddr::from([10,1,0,n]),Carrier::Tcp,Listener::Production,mono).unwrap();
        a.handshake_complete(c,mono).unwrap();
        assert_eq!(a.classify_production(c,Peer{credential:id(10),key:key(1),session:id(n),channel:[n;32],host_nonce:[41;32],device_nonce:[42;32]},now,mono).unwrap(),PeerState::Active); c
    }
    fn policy_vote(offer:&rba_protocol::v2_message::Message,accepted:u64)->rba_protocol::v2_message::Message {
        use rba_protocol::{cbor::Value as V,v2_message::{Kind,Message}};
        let p=offer.payload();Message::new(Kind::PolicyDecision,V::map([("session_id",p.get("session_id").unwrap().clone()),("revision",p.get("revision").unwrap().clone()),("digest",p.get("digest").unwrap().clone()),("accepted",V::Uint(accepted))])).unwrap()
    }
    #[test] fn policy_sync_commit_and_lost_receipt() {
        let mut a=Authority::new(ready());let t=Instant::now();let c=peer(&mut a,2,t,NOW);
        let grants=[cli(),Grant{scope:Scope::SudoService,..cli()}];
        let (offer,_)=a.policy_offer(c,id(40),principal(1,1000),1,&grants,NOW,t).unwrap();
        assert_eq!(a.store().policy(id(10)).unwrap().0.revision,1);
        assert!(a.policy_decision(c,id(40),&policy_vote(&offer,1),NOW,t).unwrap());
        assert_eq!(a.store().policy(id(10)).unwrap().0.revision,2);
        assert!(a.connection_denied(c));a.close(c);
        let c=peer(&mut a,3,t,NOW);let (offer,_)=a.policy_offer(c,id(41),principal(1,1000),2,&grants,NOW,t).unwrap();
        assert!(a.policy_decision(c,id(41),&policy_vote(&offer,1),NOW,t).unwrap());
        assert_eq!(a.store().policy(id(10)).unwrap().0.revision,2);
    }
    #[test] fn policy_sync_original_local_deadline_never_renews() {
        let mut a=Authority::new(ready());let t=Instant::now();let c=peer(&mut a,2,t,NOW);
        let grants=[cli(),Grant{scope:Scope::SudoService,..cli()}];
        let deadline=t+Duration::from_secs(3);
        let (offer,end)=a.policy_offer_until(c,id(40),principal(1,1000),1,&grants,NOW,t,deadline).unwrap();
        assert_eq!(end,deadline);
        assert!(a.policy_decision(c,id(40),&policy_vote(&offer,1),NOW+3,deadline).is_err());
        assert_eq!(a.store().policy(id(10)).unwrap().1,vec![cli()]);
    }
    #[test] fn policy_sync_decline_and_wrong_owner_never_expand() {
        let mut a=Authority::new(ready());let t=Instant::now();let grants=[cli(),Grant{scope:Scope::SudoService,..cli()}];
        let c=peer(&mut a,2,t,NOW);let (offer,_)=a.policy_offer(c,id(40),principal(1,1000),1,&grants,NOW,t).unwrap();
        assert!(!a.policy_decision(c,id(40),&policy_vote(&offer,0),NOW,t).unwrap());a.close(c);
        let c=peer(&mut a,3,t,NOW);let (offer,_)=a.policy_offer(c,id(40),principal(1,1000),1,&grants,NOW,t).unwrap();
        assert!(a.policy_decision(c,id(41),&policy_vote(&offer,1),NOW,t).is_err());
        assert_eq!(a.store().policy(id(10)).unwrap().1,vec![cli()]);
    }
    #[test] fn policy_sync_restriction_immediate_and_invalidates_offer() {
        let mut a=Authority::new(ready());let t=Instant::now();let grants=[cli(),Grant{scope:Scope::SudoService,..cli()}];
        let c=peer(&mut a,2,t,NOW);let (offer,_)=a.policy_offer(c,id(40),principal(1,1000),1,&grants,NOW,t).unwrap();
        assert!(a.restrict_policy(&principal(1,1000),id(10),1,&grants,NOW).is_err());
        a.restrict_policy(&principal(1,1000),id(10),1,&[],NOW).unwrap();
        assert!(a.policy_decision(c,id(40),&policy_vote(&offer,1),NOW,t).is_err());
        assert!(a.store().policy(id(10)).unwrap().1.is_empty());
    }
    fn prompt_rows(a:&Authority)->i64 {
        a.store().db.query_row("SELECT count(*) FROM admission WHERE kind BETWEEN 1 AND 5",[],|r|r.get(0)).unwrap()
    }
    #[test]
    fn exact_identity_grant_and_peer_before_prompt() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        let mut bad=intent(40); bad.origin=Origin::SelfCli{peer_uid:1001};
        assert!(a.begin(bad,id(10),60,NOW,t).is_err());
        let mut bad=intent(40); bad.target.generation=id(77);
        assert!(a.begin(bad,id(10),60,NOW,t).is_err());
        let mut bad=intent(40); bad.scope=Scope::SudoService;
        assert!(a.begin(bad,id(10),60,NOW,t).is_err());
        let mut bad=intent(40); bad.approver.generation=id(78);
        assert!(a.begin(bad,id(10),60,NOW,t).is_err());
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap();
        let c=a.connect(IpAddr::from([10,1,0,1]),Carrier::Tcp,Listener::Production,t).unwrap();
        a.handshake_complete(c,t).unwrap();
        assert!(a.classify_production(c,Peer{credential:id(10),key:key(2),session:id(9),channel:[9;32],host_nonce:[41;32],device_nonce:[42;32]},NOW,t).is_err());
        assert!(a.dispatch(id(40),req,c,NOW,t).is_err());
        assert_eq!(prompt_rows(&a),0);
        a.close(c);
        let c=peer(&mut a,2,t,NOW);
        assert!(a.dispatch(id(41),req,c,NOW,t).is_err());
        assert_eq!(prompt_rows(&a),0);
        let d=a.dispatch(id(40),req,c,NOW,t).unwrap();
        assert_eq!(d.channel,[2;32]); assert_eq!(d.session,id(2));
        assert_eq!(d.revision,1); assert_eq!(d.expires_at,NOW+60);
        assert_eq!(prompt_rows(&a),3);
        assert!(a.dispatch(id(40),req,c,NOW,t).is_err());
        assert_eq!(prompt_rows(&a),3);
    }
    #[test]
    fn live_ownership_cancel_and_stale_connection() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap();
        assert!(a.begin(intent(42),id(10),60,NOW,t).is_err());
        let c=peer(&mut a,2,t,NOW); let other=peer(&mut a,3,t,NOW);
        a.dispatch(id(40),req,c,NOW,t).unwrap();
        assert!(!a.cancel_peer(other,req)); assert!(!a.cancel_local(id(42),req));
        assert!(a.recheck_authorization(id(40),req,other,NOW,t).is_err());
        a.recheck_authorization(id(40),req,c,NOW,t).unwrap();
        assert!(a.cancel_peer(c,req)); assert!(a.connection_denied(c));
        assert_eq!(prompt_rows(&a),3);
        let req2=a.begin(intent(42),id(10),60,NOW,t).unwrap();
        a.dispatch(id(42),req2,other,NOW,t).unwrap();
        a.close(c); assert!(!a.cancel_peer(c,req2));
        a.recheck_authorization(id(42),req2,other,NOW,t).unwrap();
        a.close_local(id(42)); assert!(a.connection_denied(other));
        assert!(a.recheck_authorization(id(42),req2,other,NOW,t).is_err());
    }
    #[test]
    fn quota_does_not_refund_on_cancel_or_charge_ingress() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        for i in 1..=3 {
            let c=peer(&mut a,i,t,NOW);
            for _ in 0..30 { a.ingress(c,t).unwrap(); }
            assert_eq!(prompt_rows(&a),3*(i as i64-1));
            let req=a.begin(intent(40),id(10),60,NOW,t).unwrap();
            a.dispatch(id(40),req,c,NOW,t).unwrap();
            assert!(a.cancel_local(id(40),req)); a.close(c);
        }
        let c=peer(&mut a,4,t,NOW);
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap();
        assert!(a.dispatch(id(40),req,c,NOW,t).is_err());
        assert!(a.connection_denied(c)); assert_eq!(prompt_rows(&a),9); a.close(c);
        let t2=t+Duration::from_secs(60);
        let c=peer(&mut a,5,t2,NOW+60);
        let req=a.begin(intent(40),id(10),60,NOW+60,t2).unwrap();
        a.dispatch(id(40),req,c,NOW+60,t2).unwrap();
    }
    #[test]
    fn policy_revision_and_revocation_invalidate_pending() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap(); let c=peer(&mut a,1,t,NOW);
        a.dispatch(id(40),req,c,NOW,t).unwrap();
        a.replace_policy(id(10),1,&[cli()],None,NOW).unwrap();
        assert!(a.connection_denied(c)); assert!(a.recheck_authorization(id(40),req,c,NOW,t).is_err());
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap(); let c=peer(&mut a,2,t,NOW);
        assert_eq!(a.dispatch(id(40),req,c,NOW,t).unwrap().revision,2);
        a.revoke(id(10),NOW).unwrap();
        assert!(a.connection_denied(c)); assert!(a.recheck_authorization(id(40),req,c,NOW,t).is_err());
        assert!(a.begin(intent(40),id(10),60,NOW,t).is_err());
        let c=a.connect(IpAddr::from([10,1,0,3]),Carrier::Tcp,Listener::Production,t).unwrap();
        a.handshake_complete(c,t).unwrap();
        assert_eq!(a.classify_production(c,Peer{credential:id(10),key:key(1),session:id(3),channel:[3;32],host_nonce:[41;32],device_nonce:[42;32]},NOW,t).unwrap(),PeerState::RevocationOnly);
        let revoke=revoke_message(id(3),id(10),[10;32]);
        a.revoke_peer(c,&revoke,NOW,t).unwrap(); assert!(a.connection_denied(c));
        let (frame,_)=a.claim_terminal(c,NOW,t).unwrap();
        let receipt=rba_protocol::v2_message::Message::read(&mut frame.as_slice()).unwrap();
        assert_eq!(receipt.kind(),rba_protocol::v2_message::Kind::RevokeReceipt);
        assert_eq!(receipt.payload().get("session_id").unwrap().as_bytes(),Some(&id(3)[..]));
    }
    fn revoke_message(session:Id,credential:Id,token:Hash)->rba_protocol::v2_message::Message {
        use rba_protocol::{cbor::Value as V,v2_message::{Kind,Message}};
        Message::new(Kind::Revoke,V::map([("session_id",V::Bytes(session.to_vec())),("credential_id",V::Bytes(credential.to_vec())),("token",V::Bytes(token.to_vec()))])).unwrap()
    }
    #[test]
    fn terminal_revocation_rejects_wrong_session_credential_and_token() {
        for (session,credential,token) in [(id(2),id(10),[10;32]),(id(1),id(11),[10;32]),(id(1),id(10),[11;32])] {
            let mut a=Authority::new(ready());let t=Instant::now();let c=peer(&mut a,1,t,NOW);
            assert!(a.revoke_peer(c,&revoke_message(session,credential,token),NOW,t).is_err());
            assert!(a.connection_denied(c));assert!(a.claim_terminal(c,NOW,t).is_err());
            assert_eq!(a.store().peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::Active);
        }
    }
    #[test]
    fn terminal_receipt_cannot_be_claimed_by_another_connection() {
        let mut a=Authority::new(ready());let t=Instant::now();let c=peer(&mut a,1,t,NOW);let other=peer(&mut a,2,t,NOW);
        a.revoke_peer(c,&revoke_message(id(1),id(10),[10;32]),NOW,t).unwrap();
        assert!(a.claim_terminal(other,NOW,t).is_err());assert!(a.connection_denied(c));
        assert!(!a.terminal_writing(c,NOW,t));
        let (frame,deadline)=a.claim_terminal(c,NOW,t).unwrap();
        assert!(!frame.is_empty());assert_eq!(deadline,t+Duration::from_secs(5));
        assert!(a.terminal_writing(c,NOW,t));assert!(a.claim_terminal(c,NOW,t).is_err());
        assert!(a.ingress(c,t).is_err());assert!(!a.terminal_writing(c,NOW,t));
    }
    #[test]
    fn terminal_receipt_expires_and_close_removes_permission() {
        for mode in 0..4 {
            let mut a=Authority::new(ready());let t=Instant::now();let c=peer(&mut a,1,t,NOW);
            a.revoke_peer(c,&revoke_message(id(1),id(10),[10;32]),NOW,t).unwrap();
            match mode {
                0=>assert!(a.claim_terminal(c,NOW+5,t).is_err()),
                1=>assert!(a.claim_terminal(c,NOW,t+Duration::from_secs(5)).is_err()),
                2=>{a.close(c);assert!(a.claim_terminal(c,NOW,t).is_err())},
                _=>{a.claim_terminal(c,NOW,t).unwrap();assert!(!a.terminal_writing(c,NOW-1,t));a.revoke(id(10),NOW).unwrap();assert!(!a.terminal_writing(c,NOW,t));},
            }
        }
    }
    #[test]
    fn monotonic_expiry_and_wall_rollback_deny() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        let req=a.begin(intent(40),id(10),10,NOW,t).unwrap(); let c=peer(&mut a,1,t,NOW);
        a.dispatch(id(40),req,c,NOW,t).unwrap();
        assert!(a.recheck_authorization(id(40),req,c,NOW+9,t+Duration::from_secs(10)).is_err());
        assert!(a.connection_denied(c));
        let t2=t+Duration::from_secs(10);
        let req=a.begin(intent(40),id(10),60,NOW+10,t2).unwrap(); let c=peer(&mut a,2,t2,NOW+10);
        a.dispatch(id(40),req,c,NOW+10,t2).unwrap();
        assert!(matches!(a.recheck_authorization(id(40),req,c,NOW+9,t2),Err(Error::Clock)));
        assert!(a.connection_denied(c));
    }
    #[test]
    fn failed_audit_never_dispatches_or_charges() {
        let s=ready();
        s.db.execute_batch("CREATE TRIGGER deny_prompt_audit BEFORE INSERT ON audit_outbox WHEN NEW.kind='prompt' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        let mut a=Authority::new(s); let t=Instant::now();
        let req=a.begin(intent(40),id(10),60,NOW,t).unwrap(); let c=peer(&mut a,1,t,NOW);
        assert!(a.dispatch(id(40),req,c,NOW,t).is_err());
        assert_eq!(prompt_rows(&a),0); assert!(a.connection_denied(c));
        assert!(a.recheck_authorization(id(40),req,c,NOW,t).is_err());
    }
    #[test]
    fn pairing_is_single_attempt_and_stale_teardown_is_isolated() {
        let mut a=Authority::new(ready()); let t=Instant::now();
        let src=IpAddr::from([10,2,0,1]);
        assert!(a.connect(src,Carrier::Tcp,Listener::Enrollment,t).is_err());
        let p=a.begin_pairing(id(40),principal(1,1000),NOW,t).unwrap();
        assert!(a.begin_pairing(id(42),principal(1,1000),NOW,t).is_err());
        let c=a.connect(src,Carrier::Tcp,Listener::Enrollment,t).unwrap();
        assert!(a.connect(src,Carrier::Tcp,Listener::Enrollment,t).is_err());
        assert!(!a.cancel_pairing_local(id(42),p));
        assert!(a.cancel_pairing_local(id(40),p)); assert!(a.connection_denied(c));
        let p2=a.begin_pairing(id(42),principal(1,1000),NOW,t).unwrap();
        assert!(a.handshake_complete(c,t).is_err()); a.close(c);
        let c2=a.connect(src,Carrier::Tcp,Listener::Enrollment,t).unwrap();
        a.handshake_complete(c2,t).unwrap();
        assert_eq!(a.classify_enrollment(c2,NOW,t).unwrap(),p2);
        assert!(!a.cancel_pairing_peer(c,p2)); assert!(!a.cancel_pairing_peer(c2,p));
        a.close(c); assert!(!a.connection_denied(c2));
        assert!(a.cancel_pairing_peer(c2,p2)); assert!(a.connection_denied(c2));
        assert_eq!(prompt_rows(&a),0);
        assert_eq!(a.store().db.query_row("SELECT count(*) FROM admission WHERE kind=6",[],|r|r.get::<_,i64>(0)).unwrap(),2);
    }
    #[test]
    fn service_scope_needs_exact_grant_and_origin() {
        let mut s=ready();
        let g=Grant{scope:Scope::SudoService,..cli()};
        let d=policy_digest(&id(10),2,&[cli(),g]).unwrap();
        s.replace_policy(id(10),1,&[cli(),g],Some(d),NOW).unwrap();
        let mut a=Authority::new(s); let t=Instant::now();
        let mut i=intent(40); i.scope=Scope::SudoService;
        assert!(a.begin(i.clone(),id(10),60,NOW,t).is_err());
        i.origin=Origin::TrustedService(Scope::GdmSession);
        assert!(a.begin(i.clone(),id(10),60,NOW,t).is_err());
        i.origin=Origin::TrustedService(Scope::SudoService);
        let req=a.begin(i.clone(),id(10),60,NOW,t).unwrap(); let c=peer(&mut a,1,t,NOW);
        a.dispatch(id(40),req,c,NOW,t).unwrap(); assert_eq!(prompt_rows(&a),5);
        a.cancel_local(id(40),req); a.close(c);
        let req=a.begin(i,id(10),60,NOW,t).unwrap(); let c=peer(&mut a,2,t,NOW);
        assert!(a.dispatch(id(40),req,c,NOW,t).is_err()); assert_eq!(prompt_rows(&a),5);
    }

    pub(super) mod authentication {
        use super::*;
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rba_protocol::{cbor::Value as V, v2_message::{self as m, Domain, Kind, Message}};
        fn signer(n:u8)->SigningKey { let mut b=[0u8;32]; b[31]=n; SigningKey::from_slice(&b).unwrap() }
        fn b(x:impl AsRef<[u8]>)->V { V::bytes(x.as_ref().to_vec()) }
        fn count(a:&Authority)->i64 {a.store().db.query_row("SELECT count(*) FROM audit_outbox WHERE kind='auth-success'",[],|r|r.get(0)).unwrap()}
        fn start(a:&mut Authority,t:Instant)->(ConnectionId,Id,crate::v2_store::authority::AuthDispatch) {
            let c=peer(a,1,t,NOW); let req=a.begin(intent(40),id(10),60,NOW,t).unwrap();
            let out=a.start_auth(id(40),req,c,&signer(3),"rba","Authentication",NOW,t).unwrap();
            let core=out.message.payload().get("core").unwrap();
            m::verify(Domain::AuthRequest,core,&key(3),out.message.payload().get("signature").unwrap().as_bytes().unwrap()).unwrap();
            assert!(core.get("digits").is_none()); assert!(out.number.iter().all(u8::is_ascii_digit));
            (c,req,out)
        }
        fn entry(req:Id,digits:&[u8])->Message {Message::new(Kind::NumberEntry,V::map([("session_id",b(id(1))),("request_id",b(req)),("digits",V::text(std::str::from_utf8(digits).unwrap()))])).unwrap()}
        fn response(a:&mut Authority,t:Instant,n:u8)->(ConnectionId,Id,Message) {
            let (c,req,out)=start(a,t);
            let matched=a.auth_number(c,&entry(req,&*out.number),&signer(3),NOW,t).unwrap();
            let mc=matched.payload().get("core").unwrap();
            m::verify(Domain::Matched,mc,&key(3),matched.payload().get("signature").unwrap().as_bytes().unwrap()).unwrap();
            let core=V::map([("v",V::Uint(2)),("session_id",b(id(1))),("request_id",b(req)),("channel",b([1;32])),("request_hash",mc.get("request_hash").unwrap().clone()),("match_hash",b(m::hash(Domain::Matched,mc).unwrap())),("credential_id",b(id(10))),("decision",V::Uint(1))]);
            let sig:Signature=signer(n).sign(&m::transcript(Domain::AuthResponse,&core).unwrap());
            (c,req,Message::new(Kind::AuthResponse,V::map([("core",core),("signature",b(sig.to_bytes()))])).unwrap())
        }
        // A valid prefix is rebuilt for every trace. Check outcome and audit,
        // not merely whether an error/panic was raised. Never use real keys.
        pub(in crate::v2_store) fn trace(data: &[u8]) {
            let at=|i:usize| data.get(i).copied().unwrap_or(0);
            let stage=at(0)%2;
            let fault=at(1)%8;
            let mut a=Authority::new(ready());
            let t=Instant::now();
            if stage==0 {
                let(c,req,out)=start(&mut a,t);
                let good=entry(req,&*out.number);
                let mut wrong=*out.number;
                wrong[0]=if wrong[0]==b'0'{b'1'}else{b'0'};
                let result=match fault {
                    0 => a.auth_number(c,&good,&signer(3),NOW,t),
                    1 => a.auth_number(c,&entry(req,&wrong),&signer(3),NOW,t),
                    2 => a.auth_number(c,&entry(id(77),&*out.number),&signer(3),NOW,t),
                    3 => {assert!(a.cancel_local(id(40),req));a.auth_number(c,&good,&signer(3),NOW,t)},
                    4 => a.auth_number(c,&good,&signer(3),NOW+60,t+Duration::from_secs(60)),
                    5 => a.auth_number(c,&good,&signer(1),NOW,t),
                    6 => {a.close(c);a.auth_number(c,&good,&signer(3),NOW,t)},
                    _ => {assert!(!a.cancel_local(id(77),req));a.auth_number(c,&good,&signer(3),NOW,t)},
                };
                assert_eq!(result.is_ok(),fault==0||fault==7);
                // A duplicate (or retry after denial) must not reopen matching.
                assert!(a.auth_number(c,&good,&signer(3),NOW,t).is_err());
                assert_eq!(count(&a),0);
            } else {
                let(c,req,r)=response(&mut a,t,if fault==1{1}else{2});
                match fault {
                    2=>a.revoke(id(10),NOW).unwrap(),
                    3=>assert!(a.cancel_local(id(40),req)),
                    4=>{a.replace_policy(id(10),1,&[],None,NOW).unwrap();},
                    5=>a.close(c),
                    _=>{},
                }
                let clock=if fault==6{(NOW+60,t+Duration::from_secs(60))}else{(NOW,t)};
                let result=a.auth_response(c,&r,||Ok(clock));
                let allowed=fault==0||fault==7;
                assert_eq!(result.is_ok(),allowed);
                if let Ok(ok)=result{assert_eq!(ok.owner,id(40));assert_eq!(ok.interaction,id(41));}
                // Fuzzer-controlled terminal suffix exercises duplicate, cancel,
                // and stale callbacks in arbitrary bounded order.
                for &op in data.get(2..).unwrap_or_default().iter().take(32){
                    match op%3 {
                        0=>assert!(a.auth_response(c,&r,||Ok(clock)).is_err()),
                        1=>assert!(!a.cancel_local(id(40),req)),
                        _=>a.close(c),
                    }
                }
                assert!(a.auth_response(c,&r,||Ok(clock)).is_err());
                assert_eq!(count(&a),if allowed{1}else{0});
            }
        }
        #[test] fn state_trace_authentication_seeds(){for stage in 0..2{for fault in 0..8{trace(&[stage,fault,0,1,2,0]);}}}
        #[test] fn one_success_only_and_original_local_owner(){let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,2);
            let ok=a.auth_response(c,&r,||Ok((NOW,t))).unwrap();assert_eq!(ok.owner,id(40));assert_eq!(ok.interaction,id(41));assert_eq!(ok.result.kind(),Kind::AuthResult);assert_eq!(count(&a),1);
            assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert_eq!(count(&a),1);}
        #[test] fn terminal_auth_receipt_exact_and_owner_close(){
            let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,2);
            let ok=a.auth_response(c,&r,||Ok((NOW,t))).unwrap();
            assert!(a.connection_denied(c));let(frame,_)=a.claim_terminal(c,NOW,t).unwrap();
            assert_eq!(frame.as_slice(),ok.result.encode().unwrap().as_slice());
            assert!(a.terminal_writing(c,NOW,t));a.close_local(id(41));assert!(a.terminal_writing(c,NOW,t));
            a.close_local(id(40));assert!(!a.terminal_writing(c,NOW,t));
        }
        #[test] fn terminal_auth_failed_evidence_never_arms_receipt(){
            let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,1);
            assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert!(a.claim_terminal(c,NOW,t).is_err());
        }
        #[test] fn wrong_number_consumes_attempt(){let mut a=Authority::new(ready());let t=Instant::now();let(c,req,out)=start(&mut a,t);let mut wrong=*out.number;wrong[0]=if wrong[0]==b'0'{b'1'}else{b'0'};
            assert!(a.auth_number(c,&entry(req,&wrong),&signer(3),NOW,t).is_err());assert!(a.auth_number(c,&entry(req,&*out.number),&signer(3),NOW,t).is_err());assert_eq!(count(&a),0);}
        #[test] fn transport_key_cannot_authorize(){let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,1);assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert_eq!(count(&a),0);}
        #[test] fn expiry_during_final_verification_denies(){let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,2);let mut samples=0;assert!(a.auth_response(c,&r,||{samples+=1;Ok(if samples==1{(NOW,t)}else{(NOW+60,t+Duration::from_secs(60))})}).is_err());assert_eq!(count(&a),0);}
        #[test] fn revocation_invalidates_signed_evidence(){let mut a=Authority::new(ready());let t=Instant::now();let(c,_,r)=response(&mut a,t,2);a.revoke(id(10),NOW).unwrap();assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert_eq!(count(&a),0);}
        #[test] fn audit_failure_never_returns_success(){let s=ready();s.db.execute_batch("CREATE TRIGGER fail_auth BEFORE INSERT ON audit_outbox WHEN NEW.kind='auth-success' BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();let mut a=Authority::new(s);let t=Instant::now();let(c,_,r)=response(&mut a,t,2);assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert!(a.connection_denied(c));assert_eq!(count(&a),0);}
        #[test] fn cancel_is_terminal(){let mut a=Authority::new(ready());let t=Instant::now();let(c,req,r)=response(&mut a,t,2);let cancel=Message::new(Kind::Cancel,V::map([("session_id",b(id(1))),("request_id",b(req))])).unwrap();a.auth_cancel(c,&cancel,NOW,t).unwrap();assert!(a.auth_response(c,&r,||Ok((NOW,t))).is_err());assert_eq!(count(&a),0);}
    }
}

#[cfg(fuzzing)]
pub(super) fn trace_auth(data:&[u8]) { authorization::authentication::trace(data); }

#[test]
fn offline_cleanup_after_retry_expiry_and_unknown_token_rollback() {
    let mut s=ready();
    assert!(enroll(&mut s,11,1,&key(3),&key(4),&[digest(&[10;32]),digest(&[99;32])]).is_err());
    assert_eq!(s.peer_state(&key(1),&id(10),NOW).unwrap(),PeerState::Active);
    s.revoke_with_token(id(10),&key(1),&[10;32],NOW).unwrap();
    s.cleanup_tombstones(NOW+RETRY).unwrap();
    assert_eq!(s.peer_state(&key(1),&id(10),NOW+RETRY).unwrap(),PeerState::Unknown);
    let retained:Vec<u8>=s.db.query_row("SELECT token_hash FROM credentials WHERE id=?",[&id(10)[..]],|r|r.get(0)).unwrap();
    assert_eq!(retained,digest(&[10;32]).to_vec());
    // Idempotent cleanup of a revoked record cannot renew its online retry.
    enroll_at(&mut s,11,1,&key(3),&key(4),&[digest(&[10;32])],NOW+RETRY).unwrap();
    assert_eq!(s.peer_state(&key(3),&id(11),NOW+RETRY).unwrap(),PeerState::Active);
    assert_eq!(s.peer_state(&key(1),&id(10),NOW+RETRY).unwrap(),PeerState::Unknown);
}
