//! V2-only candidate daemon composition. No V1 state, IPC or transport.
//! Local operation admission remains an internal boundary for B.4; a peer
//! cannot create an operation merely by connecting to either listener.
use super::*;
use super::dispatch::{scheduler::AuthScheduler,routes::AdministrativeRoutes,LocalLink,ReceiptDelivery};
use crate::v2_store::{Principal,authority::EntryDirection};
use crate::v2_store::{Store, private_dir, private_regular, attestation::{AndroidAttestationVerifier, Policy}};
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
mod bootstrap;
mod lifecycle;
pub use lifecycle::entry;
use std::{fs::OpenOptions, io::Read, net::SocketAddr, os::unix::fs::OpenOptionsExt, path::Path};
use tokio::{net::TcpListener, task::JoinSet};
use zeroize::Zeroizing;

const MAX_TASKS: usize = 32;
const RETRY: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    host_id: String,
    bind: SocketAddr,
    enrollment_bind: SocketAddr,
    release_signer: Option<String>,
    minimum_app_version: u64,
    minimum_os_version: u64,
    minimum_os_patch: u64,
    minimum_vendor_patch: u64,
    minimum_boot_patch: u64,
}
fn exact_hex<const N:usize>(s:&str)->Result<[u8;N]> {
    if s.len()!=N*2 || !s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err(Error::Invalid)}
    let v:[u8;N]=hex::decode(s).map_err(|_|Error::Invalid)?.try_into().map_err(|_|Error::Invalid)?;
    if v==[0;N]{return Err(Error::Invalid)} Ok(v)
}
fn read_private(dir:&Path,name:&str,max:usize)->Result<Vec<u8>> {
    let path=dir.join(name);private_regular(&path,unsafe{libc::geteuid()})?;
    let mut data=Vec::new();
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(path)?.take(max as u64+1).read_to_end(&mut data)?;
    if data.is_empty()||data.len()>max{return Err(Error::Invalid)} Ok(data)
}
struct Material { host:Id, bind:SocketAddr, enrollment_bind:SocketAddr, policy:Option<Policy>, identity:Identity, signer:SigningKey }
fn load(dir:&Path)->Result<Material>{
    private_dir(dir,unsafe{libc::geteuid()})?;
    let s:Settings=serde_json::from_slice(&read_private(dir,"candidate.json",4096)?).map_err(|_|Error::Invalid)?;
    if s.bind.port()==0||s.enrollment_bind.port()==0||s.bind.port()==s.enrollment_bind.port(){return Err(Error::Invalid)}
    let host=exact_hex::<16>(&s.host_id)?;
    let policy=match s.release_signer {
        Some(release_signer)=>{
            let policy=Policy{package_name:"io.github.burtvadr.rba".into(),release_signer:exact_hex::<32>(&release_signer)?,
                minimum_app_version:s.minimum_app_version,minimum_os_version:s.minimum_os_version,minimum_os_patch:s.minimum_os_patch,
                minimum_vendor_patch:s.minimum_vendor_patch,minimum_boot_patch:s.minimum_boot_patch};
            policy.validate()?;Some(policy)
        },
        None=>{
            if [s.minimum_app_version,s.minimum_os_version,s.minimum_os_patch,s.minimum_vendor_patch,s.minimum_boot_patch]!=[0;5]{return Err(Error::Invalid)}
            None
        }
    };
    let key=Zeroizing::new(read_private(dir,"host-key.pk8",8192)?);
    let private=openssl::pkey::PKey::private_key_from_der(key.as_slice()).map_err(|_|Error::Denied)?;
    let ec=private.ec_key().map_err(|_|Error::Denied)?;
    if ec.group().curve_name()!=Some(Nid::X9_62_PRIME256V1)||ec.check_key().is_err(){return Err(Error::Denied)}
    let scalar=Zeroizing::new(ec.private_key().to_vec_padded(32).map_err(|_|Error::Denied)?);
    let signer=SigningKey::from_slice(scalar.as_slice()).map_err(|_|Error::Denied)?;
    let point:[u8;65]=signer.verifying_key().to_encoded_point(false).as_bytes().try_into().map_err(|_|Error::Denied)?;
    let identity=Identity::new(CertificateDer::from(read_private(dir,"host-cert.der",8192)?),PrivateKeyDer::Pkcs8(key.to_vec().into()),point)?;
    // Check key/certificate compatibility before opening persistent state or sockets.
    identity.config(Listener::Production,BTreeMap::new())?;
    Ok(Material{host,bind:s.bind,enrollment_bind:s.enrollment_bind,policy,identity,signer})
}
/// Idempotent initialization, serialized against every running instance.
pub fn initialize(dir:&Path)->Result<()> {
    let _lock=bootstrap::lock(dir)?;
    bootstrap::ensure(dir).map(|_|())
}
/// Local validation only, without network access.
pub fn check(dir:&Path)->Result<()> {
    let _lock=bootstrap::lock_existing(dir)?;
    let data=dir.join("instance");
    let m=load(&data)?;Store::open(&data.join("state"),m.host)?;Ok(())
}

pub(crate) struct Runtime {
    pub(crate) owner:Owner,
    identity:Identity,
    signer:SigningKey,
    pub(crate) scheduler:AuthScheduler,
    pub(crate) administrative:AdministrativeRoutes,
    enrollment_bind:SocketAddr,
}
impl Runtime {
    // Only the future verified IPC adapter may invoke this internal route.
    pub(crate) async fn enroll(&self,local:LocalLink,caller:Principal,direction:EntryDirection)->Result<ReceiptDelivery>{
        self.administrative.enroll(&self.identity,self.enrollment_bind,local,caller,direction).await
    }
    async fn production(&self,socket:TcpStream)->Result<()> {
        let channel=accept(socket,self.owner.clone(),&self.identity,Listener::Production).await?;
        match channel.purpose(){
            Some(Purpose::Authentication)=>self.scheduler.serve(channel,&self.signer).await.map(|_|()),
            Some(Purpose::Recovery|Purpose::Revocation)=>channel.peer_terminal().await,
            Some(Purpose::Policy)=>self.administrative.policy(channel).await,
            None=>Err(Error::Denied),
        }
    }
}
async fn provision(policy:Policy)->Result<AndroidAttestationVerifier>{
    tokio::task::spawn_blocking(move||AndroidAttestationVerifier::provision(policy)).await.map_err(|_|Error::State)?
}
fn install(owner:&Owner,verifier:AndroidAttestationVerifier)->Result<Instant>{
    let now=wall()?;let mono=Instant::now();
    let (_,_,expiry)=verifier.status_window(now)?;
    owner.lock().map_err(|_|Error::State)?.install_attestation(verifier,now,mono)?;
    Ok(expiry)
}
fn next_refresh(expiry:Instant)->Instant {
    let now=Instant::now();
    // Avoid a rapid fetch loop for short server cache lifetimes. Authority
    // still denies all affected operations at the actual expiry.
    expiry.checked_sub(Duration::from_secs(60)).unwrap_or(now).max(now+RETRY)
}
async fn refresh(owner:Owner,policy:Policy,first:Instant)->Result<()> {
    let mut next=next_refresh(first);
    loop {
        tokio::time::sleep_until(tokio::time::Instant::from_std(next)).await;
        next=match provision(policy.clone()).await.and_then(|v|install(&owner,v)) {
            Ok(expiry)=>next_refresh(expiry),
            Err(_)=>Instant::now()+RETRY,
        };
    }
}
/// No network listener is bound before trust provisioning and transactional revalidation.
/// A bounded task set owns accepted connections; shutdown aborts and joins all
/// of them. The legacy control socket is never opened by this runtime.
pub async fn run(dir:&Path,shutdown:impl std::future::Future<Output=()>)->Result<()> {
    let _lock=bootstrap::lock(dir)?;
    let data=bootstrap::ensure(dir)?;
    let m=load(&data)?;
    let store=Store::open(&data.join("state"),m.host)?;
    let Some(policy)=m.policy else {
        // A fresh instance is running, but it cannot authenticate anyone.
        // No verifier, authority, TCP listener, or fabricated trust window.
        let _store=store;
        return lifecycle::serve_local(dir,"running: device trust not configured; network authentication disabled",shutdown).await;
    };
    let owner=Arc::new(Mutex::new(Authority::new(store)));
    let first=install(&owner,provision(policy.clone()).await?)?;
    let listener=TcpListener::bind(m.bind).await?;
    let runtime=Arc::new(Runtime{scheduler:AuthScheduler::new(owner.clone()),administrative:AdministrativeRoutes::new(owner.clone()),owner:owner.clone(),identity:m.identity,signer:m.signer,enrollment_bind:m.enrollment_bind});
    let refresh=refresh(owner.clone(),policy,first);
    let local=lifecycle::serve_local(dir,"running: configured candidate; trusted local operation IPC pending",shutdown);
    tokio::pin!(refresh,local);
    let mut tasks=JoinSet::new();
    let mut tick=tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result=loop {
        tokio::select! {
            biased;
            result=&mut local=>break result,
            result=&mut refresh=>break result,
            _=tick.tick()=>{
                if let Err(e)=runtime.administrative.tick(){break Err(e)}
                let mut a=match owner.lock(){Ok(a)=>a,Err(_)=>break Err(Error::State)};
                let now=match wall(){Ok(now)=>now,Err(e)=>break Err(e)};
                // Expiry closes authority access; a later fresh status can
                // recover it. No synthetic trust window is ever installed.
                let _=a.maintenance(now,Instant::now());
            },
            joined=tasks.join_next(),if !tasks.is_empty()=>{
                if joined.is_some_and(|r|r.is_err()){break Err(Error::State)}
            },
            accepted=listener.accept(),if tasks.len()<MAX_TASKS=>{
                let (socket,_)=match accepted{Ok(s)=>s,Err(e)=>break Err(e.into())};
                let r=runtime.clone();tasks.spawn(async move{let _=r.production(socket).await;});
            }
        }
    };
    drop(listener);tasks.shutdown().await;result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn candidate_ids_are_exact_and_nonzero(){
        assert_eq!(exact_hex::<2>("012a").unwrap(),[1,42]);
        for s in ["0000","012A","012","012aa","0x12"," 123"] {assert!(exact_hex::<2>(s).is_err());}
    }
    #[test] fn candidate_refresh_does_not_spin_on_short_cache(){
        let before=Instant::now();let next=next_refresh(before+Duration::from_secs(1));
        assert!(next>=before+RETRY);
        let expiry=before+Duration::from_secs(3600);
        assert_eq!(next_refresh(expiry),expiry-Duration::from_secs(60));
    }
}
