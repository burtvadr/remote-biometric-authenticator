//! Versioned standalone same-user lifecycle and read-only inventory.
//! This socket cannot admit an operation, change policy or return an auth result.
use super::*;
use std::{fs,io::{Read,Write},os::unix::{fs::{FileTypeExt,MetadataExt,PermissionsExt},net::UnixStream as SyncStream,process::CommandExt},path::PathBuf,process::{Command,ExitCode,Stdio}};
use tokio::net::UnixListener;
const SOCKET:&str="daemon.sock";
const START_TIMEOUT:Duration=Duration::from_secs(15);
const IO_TIMEOUT:Duration=Duration::from_secs(2);
const MAGIC:[u8;4]=*b"RBL2";
// Store schema caps credentials at 4096. The bounded reply accommodates all
// records (ID, state, revision) without truncation or secret-bearing fields.
const MAX_REPLY:usize=512*1024;
#[derive(Clone,Copy)]
enum Request { Status, Stop, Devices }
impl Request {
    fn byte(self)->u8 {match self{Self::Status=>b'S',Self::Stop=>b'X',Self::Devices=>b'D'}}
    fn parse(value:u8)->Result<Self>{match value{b'S'=>Ok(Self::Status),b'X'=>Ok(Self::Stop),b'D'=>Ok(Self::Devices),_=>Err(Error::Invalid)}}
}
#[derive(Serialize,Deserialize,Debug,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
enum DeviceState { Paired, Connected, Revoked }
#[derive(Serialize,Deserialize,Debug,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct DeviceRow { id:String, state:DeviceState, revision:i64 }
#[derive(Serialize,Deserialize,Debug,PartialEq,Eq)]
#[serde(tag="type",rename_all="snake_case",deny_unknown_fields)]
enum Reply { Status { message:String }, Stopping, Devices { rows:Vec<DeviceRow> }, Failed }
fn inventory(owner:&Owner,peer_uid:u32)->Result<Reply>{
    let records=owner.lock().map_err(|_|Error::State)?.inventory(peer_uid)?;
    Ok(Reply::Devices{rows:records.into_iter().map(|(r,linked)| DeviceRow{
        id:hex::encode(r.id),revision:r.revision,
        state:if r.revoked{DeviceState::Revoked}else if linked{DeviceState::Connected}else{DeviceState::Paired},
    }).collect()})
}
fn reply_bytes(reply:&Reply)->Result<Vec<u8>>{
    let payload=serde_json::to_vec(reply).map_err(|_|Error::State)?;
    if payload.is_empty()||payload.len()>MAX_REPLY{return Err(Error::State)}
    let mut out=Vec::with_capacity(8+payload.len());out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());out.extend_from_slice(&payload);Ok(out)
}
fn read_reply(mut stream:impl Read,request:Request)->Result<Reply>{
    let mut header=[0u8;8];stream.read_exact(&mut header)?;
    if header[..4]!=MAGIC{return Err(Error::Invalid)}
    let size=u32::from_be_bytes(header[4..].try_into().map_err(|_|Error::Invalid)?) as usize;
    if size==0||size>MAX_REPLY{return Err(Error::Invalid)}
    let mut payload=vec![0;size];stream.read_exact(&mut payload)?;
    let mut trailing=[0u8;1];if stream.read(&mut trailing)?!=0{return Err(Error::Invalid)}
    let reply:Reply=serde_json::from_slice(&payload).map_err(|_|Error::Invalid)?;
    match (&reply,request){
        (Reply::Status{message},Request::Status) if message.starts_with("running: ")&&message.len()<=256&&message.bytes().all(|b|b.is_ascii_graphic()||b==b' ')=>(),
        (Reply::Stopping,Request::Stop)=>(),
        (Reply::Devices{rows},Request::Devices) if rows.len()<=4096=>{
            let mut previous=None;
            for row in rows{
                let id=exact_hex::<16>(&row.id)?;
                if row.revision<1||previous.is_some_and(|p|p>=id){return Err(Error::Invalid)}
                previous=Some(id);
            }
        },
        (Reply::Failed,_)=>return Err(Error::State),
        _=>return Err(Error::Invalid),
    }
    Ok(reply)
}
fn uid()->u32{unsafe{libc::geteuid()}}
fn default_dir(hardware_test:bool)->Result<PathBuf>{
    let base=std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p|p.is_absolute())
        .or_else(||std::env::var_os("HOME").map(PathBuf::from).filter(|p|p.is_absolute()).map(|p|p.join(".local/share")))
        .ok_or(Error::Invalid)?;
    Ok(base.join(if hardware_test{"rba/hardware-test-v2"}else{"rba/standalone-v2"}))
}
pub(super) fn owned_socket(path:&Path)->Result<()> {
    let m=fs::symlink_metadata(path)?;
    if !m.file_type().is_socket()||m.uid()!=uid()||m.nlink()!=1{return Err(Error::Denied)} Ok(())
}
pub(super) struct SocketGuard(pub(super) PathBuf);
impl Drop for SocketGuard{fn drop(&mut self){if owned_socket(&self.0).is_ok(){let _=fs::remove_file(&self.0);}}}
/// The outer daemon lock is held before binding and until this future exits.
pub(super) async fn serve_local(dir:&Path,status:watch::Receiver<&'static str>,owner:Owner,shutdown:impl std::future::Future<Output=()>)->Result<()> {
    let path=dir.join(SOCKET);
    match fs::symlink_metadata(&path){
        Ok(_)=>{owned_socket(&path)?;fs::remove_file(&path)?;},
        Err(e) if e.kind()==io::ErrorKind::NotFound=>(),Err(e)=>return Err(e.into()),
    }
    let listener=UnixListener::bind(&path)?;
    let _guard=SocketGuard(path.clone());
    fs::set_permissions(&path,fs::Permissions::from_mode(0o600))?;
    tokio::pin!(shutdown);
    loop{
        tokio::select!{
            biased;
            _=&mut shutdown=>return Ok(()),
            incoming=listener.accept()=>{
                let (mut stream,_)=incoming?;
                let peer_uid=match stream.peer_cred(){Ok(c) if c.uid()==uid()=>c.uid(),_=>continue};
                let exchange=async{
                    let result=async{
                        let mut frame=[0u8;5];stream.read_exact(&mut frame).await?;
                        if frame[..4]!=MAGIC{return Err(Error::Invalid)}
                        let request=Request::parse(frame[4])?;
                        // Exactly one request per stream. Half-close is required;
                        // reject trailing input before any operation is performed.
                        let mut extra=[0u8;1];if stream.read(&mut extra).await?!=0{return Err(Error::Invalid)}
                        let reply=match request{
                            Request::Status=>Reply::Status{message:(*status.borrow()).into()},
                            Request::Stop=>Reply::Stopping,
                            Request::Devices=>inventory(&owner,peer_uid).unwrap_or(Reply::Failed),
                        };
                        let bytes=reply_bytes(&reply)?;stream.write_all(&bytes).await?;stream.shutdown().await?;
                        Ok::<bool,Error>(matches!(request,Request::Stop))
                    }.await;
                    // Drain any unread input so the socket closes with EOF rather
                    // than RST (which would surface as ConnectionReset to peers).
                    let mut drain=[0u8;1024];
                    let _=tokio::time::timeout(Duration::from_millis(50),async{
                        while stream.read(&mut drain).await.unwrap_or(0)>0{}
                    }).await;
                    result
                };
                if matches!(tokio::time::timeout(IO_TIMEOUT,exchange).await,Ok(Ok(true))){return Ok(())}
            }
        }
    }
}
fn not_listening(e:&Error)->bool{
    matches!(e,Error::Io(e) if matches!(e.kind(),io::ErrorKind::NotFound|io::ErrorKind::ConnectionRefused))
}
/// Only missing/refused sockets may trigger startup. Malformed protocol,
/// incorrect ownership, timeouts and permission failures are hard errors.
fn probe(dir:&Path,request:Request)->Result<Option<Reply>>{
    match query(dir,request){Ok(r)=>Ok(Some(r)),Err(e) if not_listening(&e)=>Ok(None),Err(e)=>Err(e)}
}
pub(super) fn connect_local(dir:&Path,name:&str)->Result<SyncStream>{
    private_dir(dir,uid())?;let path=dir.join(name);owned_socket(&path)?;
    let mut stream=SyncStream::connect(path)?;
    // Verify the actual peer, not a PID or a filesystem name.
    let mut cred:libc::ucred=unsafe{std::mem::zeroed()};let mut len=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    use std::os::fd::AsRawFd;
    if unsafe{libc::getsockopt(stream.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,(&mut cred as *mut libc::ucred).cast(),&mut len)}!=0 || len as usize!=std::mem::size_of::<libc::ucred>()||cred.uid!=uid(){return Err(Error::Denied)}
    stream.set_read_timeout(Some(IO_TIMEOUT))?;stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}
fn query(dir:&Path,request:Request)->Result<Reply>{
    let mut stream=connect_local(dir,SOCKET)?;
    let mut request_bytes=[0u8;5];request_bytes[..4].copy_from_slice(&MAGIC);request_bytes[4]=request.byte();
    stream.write_all(&request_bytes)?;stream.shutdown(std::net::Shutdown::Write)?;
    // Do not turn errors after connection into an absent-server signal.
    read_reply(&mut stream,request).map_err(|_|Error::State)
}
fn status(dir:&Path)->Result<Option<String>>{
    match probe(dir,Request::Status)?{Some(Reply::Status{message})=>Ok(Some(message)),None=>Ok(None),_=>Err(Error::State)}
}
fn start(dir:&Path,hardware_test:bool)->Result<String>{
    if let Some(message)=status(dir)?{return Ok(message)}
    bootstrap::create_root(dir)?;
    let path=dir.join("daemon.log");
    let log=OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&path)?;
    private_regular(&path,uid())?;
    let m=log.metadata()?;let p=fs::symlink_metadata(&path)?;
    if !m.is_file()||m.uid()!=uid()||m.mode()&0o7777!=0o600||m.nlink()!=1||m.ino()!=p.ino()||m.dev()!=p.dev(){return Err(Error::Denied)}
    let mut cmd=Command::new(std::env::current_exe()?);
    cmd.arg(if hardware_test{"--run-hardware-test"}else{"--run-candidate"}).arg(dir).stdin(Stdio::null()).stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log));
    // Separate the daemon from the launching terminal; no shell or sudo.
    unsafe{cmd.pre_exec(||{if libc::setsid()<0{Err(io::Error::last_os_error())}else{Ok(())}});}
    let mut child=cmd.spawn()?;
    let deadline=Instant::now()+START_TIMEOUT;
    loop{
        if let Some(message)=status(dir)?{return Ok(message)}
        // A concurrent launcher may have won the lock. Keep probing for the
        // winner until the deadline instead of starting another process.
        let _=child.try_wait()?;
        if Instant::now()>=deadline{return Err(Error::State)}
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn stop(dir:&Path)->Result<()> {
    let deadline=Instant::now()+START_TIMEOUT;
    // A concurrent start may own the lock but not yet have a socket. Wait
    // for readiness and stop it, or prove the server is absent under lock.
    loop {
        match probe(dir,Request::Stop)?{
            Some(Reply::Stopping)=>break,
            Some(_)=>return Err(Error::State),
            None=>match bootstrap::lock_existing(dir){
                Ok(_lock)=>return Ok(()),
                Err(Error::Io(e)) if e.kind()==io::ErrorKind::NotFound=>return Ok(()),
                Err(Error::Io(e)) if e.kind()==io::ErrorKind::WouldBlock=>(),
                Err(e)=>return Err(e),
            },
        }
        if Instant::now()>=deadline{return Err(Error::State)}
        std::thread::sleep(Duration::from_millis(50));
    }
    loop {
        match bootstrap::lock_existing(dir){
            Ok(_lock)=>return Ok(()),
            Err(Error::Io(e)) if e.kind()==io::ErrorKind::WouldBlock=>(),
            Err(e)=>return Err(e),
        }
        if Instant::now()>=deadline{return Err(Error::State)}
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn foreground(dir:&Path,hardware_test:bool)->Result<()> {
    let rt=tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async{
        let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        run(dir,hardware_test,async{tokio::select!{_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}}).await
    })
}
/// Shared entry for the public rba executable and internal rbad artifact.
pub fn entry()->ExitCode{
    let mut args:Vec<_>=std::env::args_os().skip(1).collect();
    let hardware_test=args.first().is_some_and(|a|a=="--hardware-test");
    if hardware_test{args.remove(0);}
    let result:Result<()>=(||{
        match args.as_slice(){
            []=>{let d=default_dir(hardware_test)?;println!("RBA {}",start(&d,hardware_test)?);Ok(())},
            [a] if a=="start-server"||a=="start"=>{println!("RBA {}",start(&default_dir(hardware_test)?,hardware_test)?);Ok(())},
            [a,b] if a=="start-server"&&b=="--foreground"=>foreground(&default_dir(hardware_test)?,hardware_test),
            [a] if a=="status"=>{println!("RBA {}",status(&default_dir(hardware_test)?)?.as_deref().unwrap_or("stopped"));Ok(())},
            [a] if a=="kill-server"||a=="stop"=>{stop(&default_dir(hardware_test)?)?;println!("RBA stopped");Ok(())},
            [a] if a=="devices"=>{
                let dir=default_dir(hardware_test)?;let message=start(&dir,hardware_test)?;
                let Reply::Devices{rows}=query(&dir,Request::Devices)? else{return Err(Error::State)};
                if message.contains("network authentication disabled"){eprintln!("RBA {message}");}
                println!("List of devices attached");
                for row in rows{
                    let state=match row.state{DeviceState::Paired=>"paired",DeviceState::Connected=>"connected",DeviceState::Revoked=>"revoked"};
                    println!("{}\t{}\trevision {}",row.id,state,row.revision);
                }
                Ok(())
            },
            [a] if a=="pair"||a=="auth"=>{
                let dir=default_dir(hardware_test)?; let status=start(&dir,hardware_test)?;
                super::interaction::client(&dir,&status,if a=="pair" {super::interaction::Request::Pair(EntryDirection::DeviceTypes)} else {super::interaction::Request::Auth(None)})
            },
            [a,b,c] if a=="pair"&&b=="--code-entry"=>{
                let direction=match c.to_str(){Some("host")=>EntryDirection::HostTypes,Some("device")=>EntryDirection::DeviceTypes,_=>return Err(Error::Invalid)};
                let dir=default_dir(hardware_test)?;let status=start(&dir,hardware_test)?;super::interaction::client(&dir,&status,super::interaction::Request::Pair(direction))
            },
            [a,b,c] if a=="auth"&&b=="--device"=>{
                let id=exact_hex::<16>(c.to_str().ok_or(Error::Invalid)?)?;
                let dir=default_dir(hardware_test)?;let status=start(&dir,hardware_test)?;super::interaction::client(&dir,&status,super::interaction::Request::Auth(Some(id)))
            },
            [a,b,c,d,e] if hardware_test&&a=="configure"&&b=="--signer"&&d=="--listen"=>{
                let signer=exact_hex::<32>(c.to_str().ok_or(Error::Invalid)?)?;
                let ip=e.to_str().ok_or(Error::Invalid)?.parse().map_err(|_|Error::Invalid)?;
                bootstrap::configure_test(&default_dir(true)?,signer,ip)?;
                println!("Hardware-test profile configured. Run rba --hardware-test start-server; device operations require verified Android status.");Ok(())
            },
            [a] if a=="help"||a=="--help"=>{println!("rba [devices|pair|auth|start-server|kill-server|status|help|version]\nNo arguments or devices starts the standalone server automatically.\npair [--code-entry device|host]; auth [--device ID]. Device trust must be configured; system installation is disabled.\nOptional isolated test profile: rba --hardware-test configure --signer SHA256 --listen PRIVATE_IPV4\nPrefix test commands with --hardware-test; production state is separate.");Ok(())},
            [a] if a=="version"||a=="--version"=>{println!("rba {} (V2 candidate)",env!("CARGO_PKG_VERSION"));Ok(())},
            [a,d] if !hardware_test&&a=="--initialize-candidate"=>initialize(Path::new(d)),
            [a,d] if !hardware_test&&a=="--check-candidate"=>check(Path::new(d)),
            [a,d] if !hardware_test&&a=="--run-candidate"=>foreground(Path::new(d),false),
            [a,d] if !hardware_test&&a=="--run-hardware-test"=>foreground(Path::new(d),true),
            _=>Err(Error::Invalid),
        }
    })();
    match result{
        Ok(())=>ExitCode::SUCCESS,
        Err(Error::Invalid)=>{eprintln!("rba: unknown option, unsupported command or invalid configuration; see rba help");ExitCode::from(2)},
        Err(_)=>{eprintln!("rba: operation failed; check owner-only state and daemon.log. Existing identity was not reset.");ExitCode::FAILURE},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_inventory_is_bounded_and_exact() {
        let rows=(1u128..=4096).map(|id|DeviceRow{id:hex::encode(id.to_be_bytes()),state:DeviceState::Connected,revision:i64::MAX}).collect();
        let reply=Reply::Devices{rows};let bytes=reply_bytes(&reply).unwrap();
        assert_eq!(read_reply(bytes.as_slice(),Request::Devices).unwrap(),reply);
        assert!(read_reply(bytes.as_slice(),Request::Status).is_err());
        let mut bad=bytes.clone();bad[0]=b'X';assert!(read_reply(bad.as_slice(),Request::Devices).is_err());
        let mut bad=bytes.clone();bad[4..8].copy_from_slice(&u32::MAX.to_be_bytes());assert!(read_reply(bad.as_slice(),Request::Devices).is_err());
        let mut bad=bytes.clone();bad.push(0);assert!(read_reply(bad.as_slice(),Request::Devices).is_err());
        assert!(read_reply(&bytes[..bytes.len()-1],Request::Devices).is_err());
        let row=||DeviceRow{id:hex::encode([1;16]),state:DeviceState::Paired,revision:1};
        let bad=reply_bytes(&Reply::Devices{rows:vec![row(),row()]}).unwrap();
        assert!(read_reply(bad.as_slice(),Request::Devices).is_err());
    }
    #[test]
    fn lifecycle_inventory_uses_authoritative_store() {
        let key=|n:u8|-> [u8;65] {SigningKey::from_slice(&[n;32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap()};
        let now=wall().unwrap();
        let owner=Arc::new(Mutex::new(Authority::new(crate::v2_store::tls_test_store(&key(1),&key(2),now))));
        let Reply::Devices{rows}=inventory(&owner,1000).unwrap() else{panic!("inventory")};
        assert_eq!(rows,vec![DeviceRow{id:hex::encode([4;16]),state:DeviceState::Paired,revision:1}]);
        assert_eq!(inventory(&owner,1001).unwrap(),Reply::Devices{rows:vec![]});
        owner.lock().unwrap().revoke([4;16],now+1).unwrap();
        let Reply::Devices{rows}=inventory(&owner,1000).unwrap() else{panic!("inventory")};
        assert_eq!(rows[0].state,DeviceState::Revoked);
    }
}
