//! Standalone interactive CLI IPC. Same-UID only; not a PAM protocol.
//! A connection owns exactly one operation, never a reusable auth token.
use super::*;
use super::super::dispatch::{Approval,LocalEvent};
use crate::v2_store::{Scope,authority::{LocalIntent,Origin}};
use std::{ffi::CStr,fs,io::{BufRead,IsTerminal,Read,Write},os::unix::fs::PermissionsExt};
use tokio::{net::{UnixListener,UnixStream},sync::mpsc};

const SOCKET:&str="operation.sock";
const MAGIC:&[u8;4]=b"RBO2";
const MAX_PACKET:usize=1024;
const PAIR:u8=1;const AUTH:u8=2;
const LISTENING:u8=3;const NUMBER:u8=4;const SHOW_CODE:u8=5;const ENTER_CODE:u8=6;const REVIEW:u8=7;
const ACK:u8=8;const CODE:u8=9;const APPROVE:u8=10;
const AUTH_OK:u8=11;const PAIR_COMMITTED:u8=12;const FAILED:u8=13;
const AUTH_TIME:u64=60;const PAIR_TIME:u64=120;

#[derive(Clone,Copy)]
pub(super) enum Request {Pair(EntryDirection),Auth(Option<Id>)}
impl Request {
    fn parse(kind:u8,p:&[u8])->Result<Self>{
        match (kind,p){
            (PAIR,[0])=>Ok(Self::Pair(EntryDirection::DeviceTypes)),
            (PAIR,[1])=>Ok(Self::Pair(EntryDirection::HostTypes)),
            (AUTH,[])=>Ok(Self::Auth(None)),
            (AUTH,p) if p.len()==16=>{let id:Id=p.try_into().map_err(|_|Error::Invalid)?;if id==[0;16]{return Err(Error::Invalid)}Ok(Self::Auth(Some(id)))},
            _=>Err(Error::Invalid),
        }
    }
    fn seconds(self)->u64{match self{Self::Pair(_)=>PAIR_TIME,Self::Auth(_)=>AUTH_TIME}}
}
fn header(kind:u8,size:usize)->Result<[u8;3]>{
    if size>MAX_PACKET{return Err(Error::Invalid)}
    let n=(size as u16).to_be_bytes();Ok([kind,n[0],n[1]])
}
fn length(h:[u8;3])->Result<usize>{let n=u16::from_be_bytes([h[1],h[2]]) as usize;if n>MAX_PACKET{return Err(Error::Invalid)}Ok(n)}
async fn receive(s:&mut UnixStream)->Result<(u8,Zeroizing<Vec<u8>>)> {
    let mut h=[0;3];s.read_exact(&mut h).await?;
    let mut p=Zeroizing::new(vec![0;length(h)?]);s.read_exact(p.as_mut_slice()).await?;Ok((h[0],p))
}
async fn send(s:&mut UnixStream,kind:u8,p:&[u8])->Result<()> {
    s.write_all(&header(kind,p.len())?).await?;s.write_all(p).await?;Ok(())
}
async fn ack(s:&mut UnixStream)->Result<()> {let(k,p)=receive(s).await?;if k!=ACK||!p.is_empty(){return Err(Error::Denied)}Ok(())}
fn digits(p:&[u8])->Result<Zeroizing<[u8;6]>> {
    if p.len()!=6||!p.iter().all(u8::is_ascii_digit){return Err(Error::Invalid)}
    Ok(Zeroizing::new(p.try_into().map_err(|_|Error::Invalid)?))
}
fn account_name(uid:u32)->Result<String>{
    // Resolve from NSS using the kernel-verified UID, never $USER or IPC input.
    let mut entry:libc::passwd=unsafe{std::mem::zeroed()};let mut out=std::ptr::null_mut();let mut buf=vec![0u8;16384];
    let status=unsafe{libc::getpwuid_r(uid,&mut entry,buf.as_mut_ptr().cast(),buf.len(),&mut out)};
    if status!=0||out.is_null()||entry.pw_name.is_null()||entry.pw_uid!=uid{return Err(Error::Denied)}
    let name=unsafe{CStr::from_ptr(entry.pw_name)}.to_str().map_err(|_|Error::Denied)?;
    if name.is_empty()||name.len()>64||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b)){return Err(Error::Denied)}
    Ok(name.to_owned())
}
struct Cancel {owner:Owner,id:Id}
impl Drop for Cancel{fn drop(&mut self){if let Ok(mut a)=self.owner.lock(){a.close_local(self.id);}}}

pub(super) struct Operations {pub(super) listener:UnixListener,_guard:lifecycle::SocketGuard}
pub(super) fn bind(dir:&Path)->Result<Operations>{
    let path=dir.join(SOCKET);
    match fs::symlink_metadata(&path){Ok(_)=>{lifecycle::owned_socket(&path)?;fs::remove_file(&path)?},Err(e) if e.kind()==io::ErrorKind::NotFound=>(),Err(e)=>return Err(e.into())}
    let listener=UnixListener::bind(&path)?;
    let guard=lifecycle::SocketGuard(path.clone());fs::set_permissions(path,fs::Permissions::from_mode(0o600))?;
    Ok(Operations{listener,_guard:guard})
}
fn review_bytes(f:&crate::v2_store::authority::EnrollmentApproval)->Result<Vec<u8>>{
    if f.replaces.len()>32{return Err(Error::Invalid)}
    let mut p=Vec::new();p.extend_from_slice(&f.enrollment);
    for h in [&f.context_hash,&f.host_cert,&f.provisional_client_cert,&f.host_key_hash,&f.provisional_client_key_hash,&f.transport_key_hash,&f.biometric_key_hash]{p.extend_from_slice(h)}
    p.push(f.replaces.len() as u8);for id in &f.replaces{p.extend_from_slice(id)}Ok(p)
}
const REVIEW_BASE:usize=16+7*32+1;
fn review_context(p:&[u8])->Result<Hash>{
    if p.len()<REVIEW_BASE||p[REVIEW_BASE-1]>32||p.len()!=REVIEW_BASE+16*p[REVIEW_BASE-1] as usize{return Err(Error::Invalid)}
    p[16..48].try_into().map_err(|_|Error::Invalid)
}
// A single pending read detects EOF or unsolicited input even when waiting
// for a phone. Only the exact response to a sent event is accepted.
async fn pump(s:&mut UnixStream,mut rx:mpsc::Receiver<LocalEvent>,request:Request,interaction:Id)->Result<()> {
    let mut terminal=None;let mut phase=0u8;
    loop {
        let mut unexpected=[0u8;1];
        let event=tokio::select!{biased; _=s.read(&mut unexpected)=>return Err(Error::Denied),event=rx.recv()=>event};
        let Some(event)=event else {break};
        if terminal.is_some(){return Err(Error::State)}
        match event {
            LocalEvent::EnrollmentListening{address,shown} if matches!(request,Request::Pair(_))&&phase==0=>{
                send(s,LISTENING,address.to_string().as_bytes()).await?;ack(s).await?;shown.send(()).map_err(|_|Error::Denied)?;phase=1;
            },
            LocalEvent::DisplayNumber{digits:code,shown} if matches!(request,Request::Auth(_))&&phase==0=>{
                digits(code.as_slice())?;send(s,NUMBER,code.as_slice()).await?;ack(s).await?;shown.send(()).map_err(|_|Error::Denied)?;phase=1;
            },
            LocalEvent::DisplayPairingCode{digits:code,shown} if matches!(request,Request::Pair(EntryDirection::DeviceTypes))&&phase==1=>{
                digits(code.as_slice())?;send(s,SHOW_CODE,code.as_slice()).await?;ack(s).await?;shown.send(()).map_err(|_|Error::Denied)?;phase=2;
            },
            LocalEvent::EnterPairingCode{reply} if matches!(request,Request::Pair(EntryDirection::HostTypes))&&phase==1=>{
                send(s,ENTER_CODE,&[]).await?;let(k,p)=receive(s).await?;if k!=CODE{return Err(Error::Denied)}
                reply.send(digits(p.as_slice())?).map_err(|_|Error::Denied)?;phase=2;
            },
            LocalEvent::ReviewEnrollment{facts,reply} if matches!(request,Request::Pair(_))&&phase==2=>{
                send(s,REVIEW,&review_bytes(&facts)?).await?;let(k,p)=receive(s).await?;
                if k!=APPROVE||p.len()!=33||p[..32]!=facts.context_hash||p[32]>1{return Err(Error::Denied)}
                reply.send(Approval{context_hash:facts.context_hash,replacements:facts.replaces,initial_cli:p[32]==1}).map_err(|_|Error::Denied)?;phase=3;
            },
            LocalEvent::Authenticated{interaction:actual,expires_wall,expires_mono} if matches!(request,Request::Auth(_))&&phase==1&&actual==interaction=>{
                terminal=Some((AUTH_OK,Some((expires_wall,expires_mono))));
            },
            LocalEvent::EnrollmentCommitted{..} if matches!(request,Request::Pair(_))&&phase==3=>{terminal=Some((PAIR_COMMITTED,None));},
            _=>return Err(Error::Denied),
        }
    }
    // Keep the mailbox alive during the remote terminal write. Do not report
    // success from a receipt-delivery result or a caller-controlled field.
    let (kind,expiry)=terminal.ok_or(Error::Denied)?;
    if let Some((w,m))=expiry{if wall()?>=w||Instant::now()>=m{return Err(Error::Clock)}}
    send(s,kind,&[]).await?;s.shutdown().await?;Ok(())
}
async fn operation(s:&mut UnixStream,r:&Runtime,uid:u32,request:Request)->Result<()> {
    let name=account_name(uid)?;let owner=super::super::random::<16>()?;let interaction=super::super::random::<16>()?;
    let _cancel=Cancel{owner:r.owner.clone(),id:owner};
    let principal=r.owner.lock().map_err(|_|Error::State)?.standalone_principal(uid,&name,matches!(request,Request::Pair(_)),wall()?)?;
    match request {
        Request::Pair(direction)=>{
            let(local,rx)=LocalLink::new(owner,interaction)?;
            // The driver closes its sender on completion; on IPC failure the
            // pump drops its receiver, canceling the original driver.
            let (_,local_result)=tokio::join!(r.enroll(local,principal,direction),pump(s,rx,request,interaction));
            local_result
        },
        Request::Auth(selected)=>{
            let ids:Vec<Id>=r.owner.lock().map_err(|_|Error::State)?.inventory(uid)?.into_iter().filter(|(x,_)|!x.revoked).map(|(x,_)|x.id).collect();
            let credential=match selected {Some(id) if ids.contains(&id)=>id,None if ids.len()==1=>ids[0],_=>return Err(Error::Denied)};
            let intent=LocalIntent{owner,interaction,caller:principal.clone(),approver:principal.clone(),target:principal,scope:Scope::Cli,origin:Origin::SelfCli{peer_uid:uid}};
            let(_,rx)=r.scheduler.submit(intent,credential,AUTH_TIME,"rba-cli".into(),"Authenticate current local user".into())?;
            pump(s,rx,request,interaction).await
        }
    }
}
pub(super) async fn serve_connection(mut s:UnixStream,r:Arc<Runtime>){
    let uid=match s.peer_cred(){Ok(c) if c.uid()==unsafe{libc::geteuid()}=>c.uid(),_=>return};
    let request=tokio::time::timeout(Duration::from_secs(2),async{
        let mut magic=[0;4];s.read_exact(&mut magic).await?;if &magic!=MAGIC{return Err(Error::Invalid)}
        let(k,p)=receive(&mut s).await?;Request::parse(k,&p)
    }).await;
    let Ok(Ok(request))=request else{return};
    if !matches!(tokio::time::timeout(Duration::from_secs(request.seconds()),operation(&mut s,&r,uid,request)).await,Ok(Ok(()))){
        let _=tokio::time::timeout(Duration::from_millis(250),send(&mut s,FAILED,&[])).await;
    }
}
fn write_packet(s:&mut impl Write,k:u8,p:&[u8])->Result<()>{s.write_all(&header(k,p.len())?)?;s.write_all(p)?;Ok(())}
fn read_packet(s:&mut impl Read)->Result<(u8,Zeroizing<Vec<u8>>)>{let mut h=[0;3];s.read_exact(&mut h)?;let mut p=Zeroizing::new(vec![0;length(h)?]);s.read_exact(p.as_mut_slice())?;Ok((h[0],p))}
fn answer(prompt:&str)->Result<Zeroizing<Vec<u8>>>{
    print!("{prompt}");io::stdout().flush()?;
    let mut input=Zeroizing::new(Vec::new());io::stdin().lock().take(129).read_until(b'\n',&mut input)?;
    if input.last()!=Some(&b'\n')||input.len()>128{return Err(Error::Invalid)}
    input.pop();if input.last()==Some(&b'\r'){input.pop();}Ok(input)
}
fn show_code(p:&[u8],label:&str)->Result<()>{let code=digits(p)?;println!("{label}: {}",std::str::from_utf8(code.as_slice()).map_err(|_|Error::Invalid)?);io::stdout().flush()?;Ok(())}
fn review(s:&mut impl Write,p:&[u8])->Result<()>{
    let context=review_context(p)?;
    println!("Enrollment: {}",hex::encode(&p[..16]));
    for (i,name) in ["Context","Host certificate","Provisional device certificate","Host key","Provisional device key","Transport key","Biometric key"].iter().enumerate(){println!("{name} SHA-256: {}",hex::encode(&p[16+i*32..48+i*32]));}
    for id in p[REVIEW_BASE..].chunks_exact(16){println!("Revoke existing credential: {}",hex::encode(id));}
    let a=answer("Approve these exact fingerprints and listed revocations? Type 'yes' to allow current-user CLI authentication, 'pair-only' to enroll without a grant, or anything else to cancel: ")?;
    let grant=match a.as_slice(){b"yes"=>1,b"pair-only"=>0,_=>return Err(Error::Denied)};
    let mut p=[0u8;33];p[..32].copy_from_slice(&context);p[32]=grant;write_packet(s,APPROVE,&p)
}
pub(super) fn client(dir:&Path,status:&str,request:Request)->Result<()> {
    if status.contains("network authentication disabled"){
        if status.contains("waiting for verified Android status"){eprintln!("RBA: waiting for verified Android attestation status and listener readiness; check profile status and daemon.log.");}
        else{eprintln!("RBA: device trust is not configured; pairing and authentication are unavailable.");}
        return Err(Error::Denied)
    }
    if !io::stdin().is_terminal()||!io::stdout().is_terminal(){eprintln!("RBA: interactive terminal required.");return Err(Error::Denied)}
    let mut s=lifecycle::connect_local(dir,SOCKET)?;s.set_read_timeout(Some(Duration::from_secs(request.seconds()+2)))?;
    s.write_all(MAGIC)?;
    match request{Request::Pair(direction)=>write_packet(&mut s,PAIR,&[if direction==EntryDirection::DeviceTypes{0}else{1}])?,Request::Auth(id)=>write_packet(&mut s,AUTH,id.as_ref().map_or(&[][..],|i|i.as_slice()))?}
    if matches!(request,Request::Auth(_)){println!("Waiting for biometric confirmation. If multiple devices are paired, use auth --device ID.");io::stdout().flush()?;}
    let mut phase=0u8;
    loop {let(k,p)=read_packet(&mut s)?;match k {
        LISTENING if matches!(request,Request::Pair(_))&&phase==0=>{
            let addr:SocketAddr=std::str::from_utf8(&p).map_err(|_|Error::Invalid)?.parse().map_err(|_|Error::Invalid)?;
            println!("Waiting for authenticator on {addr}. Open enrollment on your phone.");io::stdout().flush()?;write_packet(&mut s,ACK,&[])?;phase=1;
        },
        NUMBER if matches!(request,Request::Auth(_))&&phase==0=>{show_code(&p,"Enter this number on your phone")?;write_packet(&mut s,ACK,&[])?;phase=1;},
        SHOW_CODE if matches!(request,Request::Pair(EntryDirection::DeviceTypes))&&phase==1=>{show_code(&p,"Enter this pairing code on your phone")?;write_packet(&mut s,ACK,&[])?;phase=2;},
        ENTER_CODE if matches!(request,Request::Pair(EntryDirection::HostTypes))&&phase==1&&p.is_empty()=>{let a=answer("Enter the pairing code shown on your phone: ")?;let code=digits(&a)?;write_packet(&mut s,CODE,code.as_slice())?;phase=2;},
        REVIEW if matches!(request,Request::Pair(_))&&phase==2=>{review(&mut s,&p)?;phase=3;},
        AUTH_OK if matches!(request,Request::Auth(_))&&phase==1&&p.is_empty()=>{println!("{}",if status.contains("hardware test") {"Hardware-test authentication successful (standalone only)."} else {"Authentication successful."});return Ok(())},
        PAIR_COMMITTED if matches!(request,Request::Pair(_))&&phase==3&&p.is_empty()=>{println!("Host enrollment committed. Confirm completion on your phone; recover the pending receipt if needed.");return Ok(())},
        FAILED if p.is_empty()=>{eprintln!("RBA: operation not completed locally. Check device selection, trust and connection; inspect inventory before retrying enrollment.");return Err(Error::Denied)},
        _=>return Err(Error::Invalid),
    }}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn interaction_request_exact_and_bounded(){
        assert!(matches!(Request::parse(PAIR,&[0]),Ok(Request::Pair(EntryDirection::DeviceTypes))));
        assert!(matches!(Request::parse(PAIR,&[1]),Ok(Request::Pair(EntryDirection::HostTypes))));
        assert!(Request::parse(PAIR,&[2]).is_err());assert!(Request::parse(PAIR,&[0,0]).is_err());
        assert!(matches!(Request::parse(AUTH,&[]),Ok(Request::Auth(None))));assert!(Request::parse(AUTH,&[0;16]).is_err());assert!(Request::parse(AUTH,&[1;16]).is_ok());
        assert!(Request::parse(ACK,&[]).is_err());assert!(header(1,MAX_PACKET+1).is_err());assert!(length([1,255,255]).is_err());
        assert!(digits(b"012345").is_ok());assert!(digits(b"12345").is_err());assert!(digits(b"12a456").is_err());
    }
    #[test]fn interaction_review_exact_replacements(){
        let mut p=vec![1;REVIEW_BASE+16];p[REVIEW_BASE-1]=1;assert_eq!(review_context(&p).unwrap(),[1;32]);p.push(0);assert!(review_context(&p).is_err());
    }
    #[tokio::test]async fn interaction_disconnect_drops_mailbox(){
        let(mut server,client)=UnixStream::pair().unwrap();let(local,rx)=LocalLink::new([1;16],[2;16]).unwrap();drop(client);
        assert!(pump(&mut server,rx,Request::Auth(None),[2;16]).await.is_err());drop(local);
    }
    #[tokio::test]async fn interaction_unexpected_input_rejected(){
        let(mut server,mut client)=UnixStream::pair().unwrap();let(_local,rx)=LocalLink::new([1;16],[2;16]).unwrap();client.write_all(b"x").await.unwrap();
        assert!(pump(&mut server,rx,Request::Auth(None),[2;16]).await.is_err());
    }
    #[tokio::test]async fn interaction_exact_auth_completion_after_ack(){
        let(mut server,mut client)=UnixStream::pair().unwrap();let(tx,rx)=mpsc::channel(1);
        let run=async{
            let(shown,acknowledged)=tokio::sync::oneshot::channel();
            tx.send(LocalEvent::DisplayNumber{digits:Zeroizing::new(*b"012345"),shown}).await.unwrap_or_else(|_|panic!("mailbox closed"));
            acknowledged.await.unwrap();
            tx.send(LocalEvent::Authenticated{interaction:[2;16],expires_wall:wall().unwrap()+10,expires_mono:Instant::now()+Duration::from_secs(10)}).await.unwrap_or_else(|_|panic!("mailbox closed"));
            drop(tx);
        };
        let operator=async{let(k,p)=receive(&mut client).await.unwrap();assert_eq!(k,NUMBER);assert_eq!(p.as_slice(),b"012345");send(&mut client,ACK,&[]).await.unwrap();let(k,p)=receive(&mut client).await.unwrap();assert_eq!(k,AUTH_OK);assert!(p.is_empty());};
        let(result,_,_)=tokio::time::timeout(Duration::from_secs(2),async{tokio::join!(pump(&mut server,rx,Request::Auth(None),[2;16]),run,operator)}).await.unwrap();assert!(result.is_ok());
    }
    #[tokio::test]async fn interaction_cannot_skip_number_display(){
        let(mut server,_client)=UnixStream::pair().unwrap();let(tx,rx)=mpsc::channel(1);
        tx.send(LocalEvent::Authenticated{interaction:[2;16],expires_wall:wall().unwrap()+10,expires_mono:Instant::now()+Duration::from_secs(10)}).await.unwrap_or_else(|_|panic!("mailbox closed"));drop(tx);
        assert!(pump(&mut server,rx,Request::Auth(None),[2;16]).await.is_err());
    }
    #[test]fn interaction_principal_cannot_be_renamed_or_reactivated(){
        let key=|n:u8|->[u8;65]{SigningKey::from_slice(&[n;32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()};
        let now=wall().unwrap();let mut a=Authority::new(crate::v2_store::tls_test_store(&key(1),&key(2),now));
        let p=a.standalone_principal(1000,"user1000",false,now).unwrap();assert_eq!(p.uid,1000);
        assert!(a.standalone_principal(1000,"renamed",true,now).is_err());assert!(a.standalone_principal(1001,"newuser",false,now).is_err());
        let created=a.standalone_principal(1001,"newuser",true,now).unwrap();assert_eq!(a.standalone_principal(1001,"newuser",false,now).unwrap(),created);
        a.disable_principal(created.id,now+1).unwrap();assert!(a.standalone_principal(1001,"newuser",true,now+1).is_err());
    }

}
