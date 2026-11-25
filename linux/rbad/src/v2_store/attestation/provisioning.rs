//! Fixed-origin trust provisioning. No peer-controlled URL, trust roots, status
//! body or freshness timestamps. Blocking I/O belongs on a dedicated worker,
//! never under the authorization/SQLite lock.
use super::*;
use reqwest::{blocking::Client, header::{HeaderMap,HeaderName,CACHE_CONTROL,AGE,DATE,CONTENT_TYPE,CONTENT_ENCODING,ACCEPT_ENCODING,ACCEPT}, redirect::Policy as Redirect, StatusCode};
use std::{io::Read, time::{Duration,Instant,SystemTime,UNIX_EPOCH}};

const STATUS_URL: &str = "https://android.googleapis.com/attestation/status";
const ROOTS: [(&[u8],&str);2] = [
    (include_bytes!("roots/google-android-2022.pem"),"cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc"),
    (include_bytes!("roots/google-android-2026.pem"),"6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"),
];
fn official_roots()->Result<Vec<Vec<u8>>> {
    ROOTS.iter().map(|(pem,expected)|{
        let der=ssl(ssl(X509::from_pem(pem))?.to_der())?;
        denied(hex::encode(super::super::digest(&der))==*expected)?;
        Ok(der)
    }).collect()
}
fn wall()->Result<i64>{
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_|Error::Clock)?.as_secs().try_into().map_err(|_|Error::Clock)
}
fn single(headers:&HeaderMap,name:HeaderName)->Result<Option<&str>>{
    let all=headers.get_all(name); let mut it=all.iter();
    let value=it.next().map(|v|v.to_str().map_err(|_|Error::Invalid)).transpose()?;
    denied(it.next().is_none())?; Ok(value)
}
fn seconds(s:&str)->Result<i64>{
    denied(!s.is_empty() && s.len()<=10 && s.bytes().all(|b|b.is_ascii_digit()))?;
    s.parse().map_err(|_|Error::Invalid)
}
// Cache lifetime is a ceiling, not a new validity interval on each retrieval.
// Use the greater of apparent Age and Date-based age, including transfer time.
fn remaining(headers:&HeaderMap, now:i64, elapsed:Duration)->Result<i64>{
    let directives=single(headers,CACHE_CONTROL)?.ok_or(Error::Denied)?;
    let mut max_age=None;
    for d in directives.split(',') {
        let (name,value)=match d.trim().split_once('='){Some((n,v))=>(n.trim(),Some(v.trim())),None=>(d.trim(),None)};
        if name.eq_ignore_ascii_case("no-cache") || name.eq_ignore_ascii_case("no-store") { return Err(Error::Denied); }
        if name.eq_ignore_ascii_case("max-age") {
            denied(max_age.is_none())?; max_age=Some(seconds(value.ok_or(Error::Invalid)?)?);
        }
    }
    let cap=max_age.ok_or(Error::Denied)?.min(DAY);
    let age=single(headers,AGE)?.map(seconds).transpose()?.unwrap_or(0);
    let date=httpdate::parse_http_date(single(headers,DATE)?.ok_or(Error::Denied)?).map_err(|_|Error::Invalid)?;
    let date:i64=date.duration_since(UNIX_EPOCH).map_err(|_|Error::Clock)?.as_secs().try_into().map_err(|_|Error::Clock)?;
    // Permit only tiny Date rounding/skew; do not grant future freshness.
    denied(date<=now.checked_add(5).ok_or(Error::Clock)?)?;
    let elapsed:i64=elapsed.as_secs().checked_add(1).ok_or(Error::Clock)?.try_into().map_err(|_|Error::Clock)?;
    let used=now.checked_sub(date).ok_or(Error::Clock)?.max(age.checked_add(elapsed).ok_or(Error::Clock)?).max(0);
    let left=cap.checked_sub(used).ok_or(Error::Clock)?;
    denied(left>0)?; Ok(left)
}
fn fetch_status()->Result<StatusSnapshot>{
    let start=Instant::now(); let started_at=wall()?;
    let client=Client::builder().https_only(true).redirect(Redirect::none()).no_proxy()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(20))
        .build().map_err(|_|Error::Denied)?;
    let response=client.get(STATUS_URL).header(ACCEPT,"application/json").header(ACCEPT_ENCODING,"identity")
        .send().map_err(|_|Error::Denied)?;
    denied(response.status()==StatusCode::OK && response.url().as_str()==STATUS_URL)?;
    let headers=response.headers().clone();
    denied(single(&headers,CONTENT_TYPE)?.is_some_and(|v|v.split(';').next().is_some_and(|m|m.trim().eq_ignore_ascii_case("application/json"))))?;
    denied(single(&headers,CONTENT_ENCODING)?.is_none_or(|v|v.eq_ignore_ascii_case("identity")))?;
    denied(response.content_length().is_none_or(|n|n<=MAX_STATUS as u64))?;
    let mut body=Vec::new(); response.take((MAX_STATUS+1) as u64).read_to_end(&mut body)?;
    denied(!body.is_empty() && body.len()<=MAX_STATUS)?;
    let finished=Instant::now(); let now=wall()?; let elapsed=finished.duration_since(start);
    denied(now>=started_at && elapsed<=Duration::from_secs(20))?;
    let left=remaining(&headers,now,elapsed)?;
    let expires=now.checked_add(left).ok_or(Error::Clock)?;
    let mut snapshot=StatusSnapshot::from_authenticated_response(&body,now,expires)?;
    snapshot.deadline=Some(finished.checked_add(Duration::from_secs(left as u64)).ok_or(Error::Clock)?);
    snapshot.fresh(wall()?)?; Ok(snapshot)
}
impl AndroidAttestationVerifier {
    /// Fetch a new official status list and construct a verifier with only the
    /// two reviewed Google roots. The release identity/floors come from trusted
    /// administrator configuration. Never call from the daemon request loop.
    pub fn provision(policy:Policy)->Result<Self>{
        policy.validate()?; let roots=official_roots()?;
        Self::new(policy,&roots,fetch_status()?)
    }
    pub(crate) fn status_window(&self,now:i64)->Result<(i64,i64,Instant)>{
        self.status.fresh(now)?;
        Ok((self.status.fetched_at,self.status.expires_at,self.status.deadline.ok_or(Error::Denied)?))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn headers(cache:&str,age:Option<&str>,date:&str)->HeaderMap{
        let mut h=HeaderMap::new(); h.insert(CACHE_CONTROL,cache.parse().unwrap());h.insert(DATE,date.parse().unwrap());
        if let Some(a)=age{h.insert(AGE,a.parse().unwrap());} h
    }
    const NOW:i64=1767225600;
    const DATE_NOW:&str="Thu, 01 Jan 2026 00:00:00 GMT";
    #[test] fn pinned_google_roots_have_expected_identity(){
        let roots=official_roots().unwrap(); assert_eq!(roots.len(),2);
        for der in roots{let x=ssl(X509::from_der(&der)).unwrap();let key=x.public_key().unwrap();assert!(x.verify(&key).unwrap());assert!(parse_cert(&der).unwrap().is_ca());}
    }
    #[test] fn cache_lifetime_never_renews_age(){
        let h=headers("public, max-age=3600",Some("120"),DATE_NOW);
        assert_eq!(remaining(&h,NOW+150,Duration::from_secs(2)).unwrap(),3450);
        assert_eq!(remaining(&h,NOW,Duration::from_secs(2)).unwrap(),3477);
        assert!(remaining(&h,NOW+3600,Duration::ZERO).is_err());
        assert_eq!(remaining(&headers("max-age=999999",None,DATE_NOW),NOW,Duration::ZERO).unwrap(),DAY-1);
    }
    #[test] fn malformed_or_uncacheable_responses_are_rejected(){
        for s in ["public","max-age=0","max-age=1","max-age=3600, max-age=3600","max-age=-1","no-cache, max-age=300","no-store,max-age=300"]{
            assert!(remaining(&headers(s,None,DATE_NOW),NOW,Duration::ZERO).is_err(),"{s}");
        }
        assert!(remaining(&headers("max-age=3600",Some("-1"),DATE_NOW),NOW,Duration::ZERO).is_err());
        assert!(remaining(&headers("max-age=3600",None,DATE_NOW),NOW-6,Duration::ZERO).is_err());
        let mut h=headers("max-age=3600",None,DATE_NOW);h.append(CACHE_CONTROL,"max-age=3600".parse().unwrap());
        assert!(remaining(&h,NOW,Duration::ZERO).is_err());
    }
}
