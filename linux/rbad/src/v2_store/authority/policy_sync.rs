//! Explicit locally authorized policy operations. Removals are committed without
//! a device vote. Expansions are committed only on the owning mTLS decision.
use super::*;
use rba_protocol::{cbor::Value as V,v2_message::{Kind,Message}};

pub(super) struct Offer {
    pub(super) owner:Id,
    pub(super) credential:Id,
    pub(super) expires_wall:i64,
    pub(super) expires_mono:Instant,
    caller:Principal,
    base:Policy,
    next:Policy,
    grants:Vec<Grant>,
    session:Id,
}
fn b(x:&[u8])->V { V::Bytes(x.to_vec()) }
impl Authority {
    fn policy_actor(&self,caller:&Principal,credential:Id)->Result<()> {
        if !principal_matches(&self.store.db,caller)? {return Err(Error::Denied)}
        let owner:bool=self.store.db.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE id=? AND owner=? AND revoked_at IS NULL)",params![&credential[..],&caller.id[..]],|r|r.get(0))?;
        if !owner {return Err(Error::Denied)} Ok(())
    }
    /// Trusted local adapter may remove grants even while the phone is offline.
    /// No consent digest is accepted from the adapter. Mixed changes remove
    /// rights first via this API, then propose the remaining expansion.
    pub(crate) fn restrict_policy(&mut self,caller:&Principal,credential:Id,expected:i64,grants:&[Grant],now:i64)->Result<Policy>{
        self.policy_actor(caller,credential)?;
        let (old,current)=self.store.policy(credential)?;
        if old.revision!=expected || grants.iter().any(|g|!current.contains(g)){return Err(Error::Denied)}
        let next=self.store.replace_policy(credential,expected,grants,None,now)?;
        self.invalidate_credential(credential);Ok(next)
    }
    /// Caller/owner are established by the trusted local adapter, never a wire
    /// message. `desired` is either the current committed policy (recovery) or
    /// a pure expansion; mixed changes must restrict before offering.
    #[cfg(any(test,fuzzing))]
    pub(crate) fn policy_offer(&mut self,conn:ConnectionId,owner:Id,caller:Principal,expected:i64,desired:&[Grant],now:i64,mono:Instant)->Result<(Message,Instant)> {
        self.policy_offer_until(conn,owner,caller,expected,desired,now,mono,mono.checked_add(Duration::from_secs(60)).ok_or(Error::Clock)?)
    }
    pub(crate) fn policy_offer_until(&mut self,conn:ConnectionId,owner:Id,caller:Principal,expected:i64,desired:&[Grant],now:i64,mono:Instant,local_deadline:Instant)->Result<(Message,Instant)> {
        let result=(||{
            self.expire(now,mono)?;
            let p=self.peers.get(&conn).ok_or(Error::Denied)?;
            if !valid_id(&owner)||p.used||p.access!=PeerState::Active{return Err(Error::Denied)}
            let peer=p.peer.clone(); self.policy_actor(&caller,peer.credential)?;
            if self.store.peer_state(&peer.key,&peer.credential,now)?!=PeerState::Active || self.policy_offers.values().any(|o|o.credential==peer.credential||o.owner==owner){return Err(Error::Denied)}
            let (base,current)=self.store.policy(peer.credential)?;
            if base.revision!=expected || desired.len()>32 || current.iter().any(|g|!desired.contains(g)) || desired.iter().any(|g|g.approver!=caller.id) {return Err(Error::Denied)}
            for g in desired {
                let active:bool=self.store.db.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE id=? AND active=1)",[&g.target[..]],|r|r.get(0))?;
                if !active{return Err(Error::Denied)}
            }
            let revision=if desired.len()==current.len(){base.revision}else{base.revision.checked_add(1).ok_or(Error::State)?};
            let next=Policy{revision,digest:policy_digest(&peer.credential,revision,desired)?};
            if revision==base.revision && next!=base{return Err(Error::Denied)}
            let core=policy_core(&peer.credential,revision,desired)?;
            let message=Message::new(Kind::PolicyOffer,V::map([("session_id",b(&peer.session)),("revision",V::Uint(revision as u64)),("grants",core.get("grants").ok_or(Error::State)?.clone()),("digest",b(&next.digest))])).map_err(|_|Error::Invalid)?;
            self.resources.local(caller.id,mono)?;
            let expires_mono=mono.checked_add(Duration::from_secs(60)).ok_or(Error::Clock)?.min(local_deadline);
            let remaining=expires_mono.checked_duration_since(mono).ok_or(Error::Clock)?.as_secs();
            if remaining==0 || Instant::now()>=expires_mono{return Err(Error::Denied)}
            let expires_wall=now.checked_add(remaining as i64).ok_or(Error::Clock)?;
            self.peers.get_mut(&conn).ok_or(Error::State)?.used=true;
            self.policy_offers.insert(conn,Offer{owner,credential:peer.credential,expires_wall,expires_mono,caller,base,next,grants:desired.to_vec(),session:peer.session});
            Ok((message,expires_mono))
        })();
        if result.is_err(){self.deny_connection(conn)} result
    }
    pub(crate) fn policy_decision(&mut self,conn:ConnectionId,owner:Id,message:&Message,now:i64,mono:Instant)->Result<bool>{
        let result=(||{
            self.expire(now,mono)?;
            let offer=self.policy_offers.remove(&conn).ok_or(Error::Denied)?;
            let p=self.peers.get(&conn).ok_or(Error::Denied)?;
            if offer.owner!=owner || p.peer.credential!=offer.credential || p.peer.session!=offer.session || !p.used || p.access!=PeerState::Active || self.store.peer_state(&p.peer.key,&offer.credential,now)?!=PeerState::Active {return Err(Error::Denied)}
            self.policy_actor(&offer.caller,offer.credential)?;
            let v=message.payload();
            if message.kind()!=Kind::PolicyDecision || v.get("session_id")!=Some(&b(&offer.session)) || v.get("revision")!=Some(&V::Uint(offer.next.revision as u64)) || v.get("digest")!=Some(&b(&offer.next.digest)) || self.store.policy(offer.credential)?.0!=offer.base {return Err(Error::Denied)}
            if v.get("accepted")==Some(&V::Uint(0)){return Ok(None)}
            if v.get("accepted")!=Some(&V::Uint(1)) || Instant::now()>=offer.expires_mono{return Err(Error::Denied)}
            let receipt=Message::new(Kind::PolicyReceipt,V::map([("session_id",b(&offer.session)),("revision",V::Uint(offer.next.revision as u64)),("digest",b(&offer.next.digest))])).map_err(|_|Error::Invalid)?;
            if offer.next!=offer.base {
                let committed=self.store.replace_policy(offer.credential,offer.base.revision,&offer.grants,Some(offer.next.digest),now)?;
                if committed!=offer.next{return Err(Error::State)}
                self.invalidate_credential(offer.credential);
            }
            Ok(Some((offer,receipt)))
        })();
        self.deny_connection(conn);
        if let Some((offer,receipt))=result? {
            self.arm_terminal(conn,offer.credential,Some(owner),&receipt,now,mono,Some((offer.expires_wall,offer.expires_mono)))?;
            Ok(true)
        } else {Ok(false)}
    }
}
