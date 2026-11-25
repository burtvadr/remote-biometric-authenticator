//! Recheck immutable enrolled chains against the new official status snapshot
//! and current release policy. No extension of the original assurance window.
use super::*;
use crate::v2_store::{self as store, Evidence, Id, Store};
use rba_protocol::{cbor::Value, v2_wire};
use rusqlite::params;

fn chain(encoded:&[u8])->Result<Vec<Vec<u8>>>{
    let value=v2_wire::decode_payload(encoded).map_err(|_|Error::Invalid)?;
    let Value::Map(fields)=&value else{return Err(Error::Invalid)};
    denied(fields.len()==1)?;
    let Some(Value::Array(certs))=value.get("chain") else{return Err(Error::Invalid)};
    denied((1..=MAX_CHAIN).contains(&certs.len()))?;
    certs.iter().map(|v|{
        let der=v.as_bytes().ok_or(Error::Invalid)?;
        denied(!der.is_empty() && der.len()<=MAX_CERT)?; Ok(der.to_vec())
    }).collect()
}
impl AndroidAttestationVerifier {
    fn revalidate_role(&mut self, encoded:&[u8], key:&[u8], biometric:bool, now:i64)->Result<AttestationValidity>{
        let certs=chain(encoded)?;
        let leaf=parse_cert(&certs[0])?;
        let ext=leaf.extensions().iter().find(|x|x.oid.to_id_string()==OID).ok_or(Error::Denied)?;
        // The original challenge was verified at enrollment. Re-reading that
        // signed value does NOT authenticate a new challenge or a new key.
        let original=description::original_challenge(ext.value)?;
        self.verify(AttestationRequest{chain:&certs,expected_key:key.try_into().map_err(|_|Error::Invalid)?,challenge:original,biometric,now})
    }
    fn revalidate(&mut self,e:&Evidence,now:i64)->Result<i64>{
        denied(e.attested_at<=now && now<e.assurance_until && e.assurance_until.checked_sub(e.attested_at).is_some_and(|n|n<=30*DAY))?;
        let a=self.revalidate_role(&e.transport_chain,&e.transport_key,false,now)?;
        let b=self.revalidate_role(&e.biometric_chain,&e.biometric_key,true,now)?;
        denied(e.transport_key!=e.biometric_key && e.assurance_until<=a.assurance_until.min(b.assurance_until))?;
        // Preserve the original attested_at and assurance_until. A status
        // update never manufactures fresh key-creation evidence.
        Ok(a.status_until.min(b.status_until))
    }
}
#[derive(Debug,Default,PartialEq,Eq)]
pub struct RefreshReport { pub refreshed:usize, pub revoked:usize }
impl Store {
    /// One transaction for all existing non-revoked credentials and audit
    /// events. Snapshot expiration or a storage failure rolls everything back.
    pub(in crate::v2_store) fn revalidate_attestation(&mut self,v:&mut AndroidAttestationVerifier,now:i64)->Result<RefreshReport>{
        v.status.fresh(now)?;
        let t=self.tx()?; store::observe(&t,now)?;
        let ids:Vec<Id>={
            let mut s=t.prepare("SELECT id FROM credentials WHERE revoked_at IS NULL ORDER BY id")?;
            let rows=s.query_map([],|r|r.get::<_,Vec<u8>>(0))?;
            let mut out=Vec::new();
            for row in rows{out.push(store::as_id(row?)?);} out
        };
        let mut report=RefreshReport::default();
        for id in ids {
            v.status.fresh(now)?;
            let e=t.query_row("SELECT transport_key,biometric_key,transport_chain,biometric_chain,attested_at,assurance_until,status_checked_at,status_until FROM credentials WHERE id=? AND revoked_at IS NULL",[&id[..]],|r|Ok(Evidence{transport_key:r.get(0)?,biometric_key:r.get(1)?,transport_chain:r.get(2)?,biometric_chain:r.get(3)?,attested_at:r.get(4)?,assurance_until:r.get(5)?,status_checked_at:r.get(6)?,status_until:r.get(7)?}))?;
            // Clock regression is a global failure, not proof that a key was revoked.
            if now<e.status_checked_at{return Err(Error::Clock);}
            let checked=v.revalidate(&e,now);
            v.status.fresh(now)?;
            match checked {
                Ok(until)=>{
                    if t.execute("UPDATE credentials SET status_checked_at=?,status_until=? WHERE id=? AND revoked_at IS NULL",params![now,until,&id[..]])?!=1{return Err(Error::State);}
                    store::audit(&t,"status-refresh",&id,now)?;report.refreshed+=1;
                }
                Err(Error::Denied|Error::Invalid)=>{
                    // A valid fresh status/policy update makes this immutable
                    // evidence unacceptable. Require new enrollment; preserve
                    // the existing revocation-only recovery semantics.
                    store::revoke_tx(&t,&id,now)?;report.revoked+=1;
                }
                Err(e)=>return Err(e),
            }
        }
        v.status.fresh(now)?;t.commit()?;Ok(report)
    }
}
