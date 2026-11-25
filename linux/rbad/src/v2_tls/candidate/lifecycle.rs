//! Standalone same-user lifecycle. This socket is NOT the B.4 authentication
//! IPC and cannot admit an operation, change policy or return an auth result.
use super::*;
use std::{fs,io::{Read,Write},os::unix::{fs::{FileTypeExt,MetadataExt,PermissionsExt},net::UnixStream as SyncStream,process::CommandExt},path::PathBuf,process::{Command,ExitCode,Stdio}};
use tokio::net::UnixListener;
const SOCKET:&str="daemon.sock";
const START_TIMEOUT:Duration=Duration::from_secs(15);
const IO_TIMEOUT:Duration=Duration::from_millis(300);
fn uid()->u32{unsafe{libc::geteuid()}}
fn default_dir()->Result<PathBuf>{
    let base=std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p|p.is_absolute())
        .or_else(||std::env::var_os("HOME").map(PathBuf::from).filter(|p|p.is_absolute()).map(|p|p.join(".local/share")))
        .ok_or(Error::Invalid)?;
    Ok(base.join("rba/standalone-v2"))
}
fn owned_socket(path:&Path)->Result<()> {
    let m=fs::symlink_metadata(path)?;
    if !m.file_type().is_socket()||m.uid()!=uid()||m.nlink()!=1{return Err(Error::Denied)} Ok(())
}
struct SocketGuard(PathBuf);
impl Drop for SocketGuard{fn drop(&mut self){if owned_socket(&self.0).is_ok(){let _=fs::remove_file(&self.0);}}}
/// The outer daemon lock is held before binding and until this future exits.
pub(super) async fn serve_local(dir:&Path,status:&'static str,shutdown:impl std::future::Future<Output=()>)->Result<()> {
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
                if stream.peer_cred()?.uid()!=uid(){continue}
                let exchange=async{
                    let mut command=[0u8;1];stream.read_exact(&mut command).await?;
                    let reply=match command[0]{b'S'=>status,b'X'=>"stopping",_=>"invalid lifecycle command"};
                    stream.write_all(reply.as_bytes()).await?;stream.shutdown().await?;
                    Ok::<bool,io::Error>(command[0]==b'X')
                };
                if matches!(tokio::time::timeout(IO_TIMEOUT,exchange).await,Ok(Ok(true))){return Ok(())}
            }
        }
    }
}
fn query(dir:&Path,command:u8)->Result<String>{
    private_dir(dir,uid())?;let path=dir.join(SOCKET);owned_socket(&path)?;
    let mut stream=SyncStream::connect(path)?;
    // Verify the actual peer, not a PID or a filesystem name.
    let mut cred:libc::ucred=unsafe{std::mem::zeroed()};let mut len=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    use std::os::fd::AsRawFd;
    if unsafe{libc::getsockopt(stream.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,(&mut cred as *mut libc::ucred).cast(),&mut len)}!=0 || len as usize!=std::mem::size_of::<libc::ucred>()||cred.uid!=uid(){return Err(Error::Denied)}
    stream.set_read_timeout(Some(IO_TIMEOUT))?;stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&[command])?;let mut bytes=Vec::new();stream.take(256).read_to_end(&mut bytes)?;
    let reply=String::from_utf8(bytes).map_err(|_|Error::Invalid)?;
    if (command==b'S'&&reply.starts_with("running: "))||(command==b'X'&&reply=="stopping"){Ok(reply)}else{Err(Error::State)}
}
fn start(dir:&Path)->Result<String>{
    if let Ok(status)=query(dir,b'S'){return Ok(status)}
    bootstrap::create_root(dir)?;
    let path=dir.join("daemon.log");
    let log=OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&path)?;
    private_regular(&path,uid())?;
    let m=log.metadata()?;let p=fs::symlink_metadata(&path)?;
    if !m.is_file()||m.uid()!=uid()||m.mode()&0o7777!=0o600||m.nlink()!=1||m.ino()!=p.ino()||m.dev()!=p.dev(){return Err(Error::Denied)}
    let mut cmd=Command::new(std::env::current_exe()?);
    cmd.arg("--run-candidate").arg(dir).stdin(Stdio::null()).stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log));
    // Separate the daemon from the launching terminal; no shell or sudo.
    unsafe{cmd.pre_exec(||{if libc::setsid()<0{Err(io::Error::last_os_error())}else{Ok(())}});}
    let mut child=cmd.spawn()?;
    let deadline=Instant::now()+START_TIMEOUT;
    loop{
        if let Ok(status)=query(dir,b'S'){return Ok(status)}
        // A concurrent launcher may have won the lock. Keep probing for the
        // winner until the deadline instead of starting another process.
        let _=child.try_wait()?;
        if Instant::now()>=deadline{return Err(Error::State)}
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn stop(dir:&Path)->Result<()> {
    query(dir,b'X')?;
    let deadline=Instant::now()+START_TIMEOUT;
    loop {
        if let Ok(_lock)=bootstrap::lock_existing(dir){return Ok(())}
        if Instant::now()>=deadline{return Err(Error::State)}
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn foreground(dir:&Path)->Result<()> {
    let rt=tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async{
        let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        run(dir,async{tokio::select!{_ = tokio::signal::ctrl_c()=>{},_ = term.recv()=>{}}}).await
    })
}
/// Shared entry for the public rba executable and internal rbad artifact.
pub fn entry()->ExitCode{
    let args:Vec<_>=std::env::args_os().skip(1).collect();
    let result:Result<()>=(||{
        match args.as_slice(){
            []=>{let d=default_dir()?;println!("RBA {}",start(&d)?);Ok(())},
            [a] if a=="start"=>{println!("RBA {}",start(&default_dir()?)?);Ok(())},
            [a] if a=="status"=>{println!("RBA {}",query(&default_dir()?,b'S')?);Ok(())},
            [a] if a=="stop"=>{stop(&default_dir()?)?;println!("RBA stopped");Ok(())},
            [a] if a=="help"||a=="--help"=>{println!("rba [start|status|stop|help]\nRootless standalone candidate. Device trust and authentication IPC are not configured by first run. System installation is disabled.");Ok(())},
            [a] if a=="version"||a=="--version"=>{println!("rba {} (V2 candidate)",env!("CARGO_PKG_VERSION"));Ok(())},
            [a,d] if a=="--initialize-candidate"=>initialize(Path::new(d)),
            [a,d] if a=="--check-candidate"=>check(Path::new(d)),
            [a,d] if a=="--run-candidate"=>foreground(Path::new(d)),
            _=>Err(Error::Invalid),
        }
    })();
    match result{
        Ok(())=>ExitCode::SUCCESS,
        Err(Error::Invalid)=>{eprintln!("rba: unknown option, unsupported command or invalid configuration; see rba help");ExitCode::from(2)},
        Err(_)=>{eprintln!("rba: operation failed; check owner-only state and daemon.log. Existing identity was not reset.");ExitCode::FAILURE},
    }
}
