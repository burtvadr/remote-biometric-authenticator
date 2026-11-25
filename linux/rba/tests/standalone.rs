//! End-to-end public binary test; execute as an ordinary Linux user.
use std::{fs,path::PathBuf,process::{Command,Stdio},time::{SystemTime,UNIX_EPOCH}};

struct Fixture(PathBuf);
impl Fixture {
    fn new()->Self {
        let home=PathBuf::from(std::env::var_os("HOME").expect("owner-controlled HOME required"));
        let stamp=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        Self(home.join(format!(".rba-standalone-test-{}-{stamp}",std::process::id())))
    }
    fn cmd(&self)->Command {
        let mut c=Command::new(env!("CARGO_BIN_EXE_rba"));c.env("XDG_DATA_HOME",&self.0);c
    }
    fn run(&self,args:&[&str])->String {
        let o=self.cmd().args(args).output().unwrap();
        assert!(o.status.success(),"{}",String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }
    fn data(&self)->PathBuf {self.0.join("rba/standalone-v2/instance")}
}
impl Drop for Fixture {
    fn drop(&mut self){let _=self.cmd().args(["--hardware-test","kill-server"]).stdout(Stdio::null()).stderr(Stdio::null()).status();let _=self.cmd().arg("kill-server").stdout(Stdio::null()).stderr(Stdio::null()).status();let _=fs::remove_dir_all(&self.0);}
}
#[test]
fn zero_config_concurrent_start_and_restart_preserve_identity(){
    let f=Fixture::new();
    let mut a=f.cmd().arg("devices").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let b=f.cmd().arg("start-server").output().unwrap();
    assert!(a.wait().unwrap().success());assert!(b.status.success());
    assert!(f.run(&["status"]).contains("network authentication disabled"));
    assert_eq!(f.run(&["devices"]).trim(),"List of devices attached");
    let data=f.data();let key=fs::read(data.join("host-key.pk8")).unwrap();
    let settings=fs::read(data.join("candidate.json")).unwrap();
    let cert=fs::read(data.join("host-cert.der")).unwrap();
    assert!(data.join("state/state.sqlite3").is_file());
    let outer=data.parent().unwrap();
    let duplicate=f.cmd().arg("--run-candidate").arg(outer).output().unwrap();
    assert!(!duplicate.status.success());
    f.run(&["kill-server"]);
    assert_eq!(f.run(&["status"]).trim(),"RBA stopped");
    f.run(&[]);
    assert_eq!(fs::read(data.join("host-key.pk8")).unwrap(),key);
    assert_eq!(fs::read(data.join("candidate.json")).unwrap(),settings);
    assert_eq!(fs::read(data.join("host-cert.der")).unwrap(),cert);
    f.run(&["kill-server"]);
}

#[test]
fn read_only_commands_and_kill_server_do_not_initialize() {
    let f=Fixture::new();
    assert!(f.run(&["help"]).contains("start-server"));
    f.run(&["version"]);
    assert_eq!(f.run(&["status"]).trim(),"RBA stopped");
    f.run(&["kill-server"]);
    assert!(!f.0.exists());
}
#[test]
fn stale_socket_is_recovered_without_replacing_identity() {
    use std::os::unix::net::UnixListener;
    let f=Fixture::new();
    f.run(&["devices"]);f.run(&["kill-server"]);
    let data=f.data();let key=fs::read(data.join("host-key.pk8")).unwrap();
    let socket=data.parent().unwrap().join("daemon.sock");
    drop(UnixListener::bind(&socket).unwrap());
    assert_eq!(f.run(&["devices"]).trim(),"List of devices attached");
    assert_eq!(fs::read(data.join("host-key.pk8")).unwrap(),key);
    f.run(&["kill-server"]);
    assert!(!socket.exists());
}
#[test]
fn malformed_live_socket_is_not_replaced() {
    use std::io::{Read,Write};
    use std::os::unix::net::UnixListener;
    let f=Fixture::new();
    f.run(&["devices"]);f.run(&["kill-server"]);
    let data=f.data();let key=fs::read(data.join("host-key.pk8")).unwrap();
    let socket=data.parent().unwrap().join("daemon.sock");
    let listener=UnixListener::bind(&socket).unwrap();
    let fake=std::thread::spawn(move||{
        let (mut stream,_)=listener.accept().unwrap();let mut request=Vec::new();
        stream.read_to_end(&mut request).unwrap();assert_eq!(request.as_slice(),b"RBL2S");
        stream.write_all(b"BAD!\0\0\0\0").unwrap();
    });
    let result=f.cmd().arg("devices").output().unwrap();
    fake.join().unwrap();assert!(!result.status.success());
    assert!(socket.exists());assert_eq!(fs::read(data.join("host-key.pk8")).unwrap(),key);
    assert_eq!(f.run(&["status"]).trim(),"RBA stopped");
}

#[test]
fn invalid_lifecycle_request_cannot_stop_server() {
    use std::{io::{Read,Write},net::Shutdown,os::unix::net::UnixStream,time::Duration};
    let f=Fixture::new();f.run(&["start-server"]);
    let socket=f.data().parent().unwrap().join("daemon.sock");
    for request in [b"RBL2Xextra".as_slice(),b"OLD!X".as_slice(),b"RBL2?".as_slice()] {
        let mut stream=UnixStream::connect(&socket).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream.write_all(request).unwrap();stream.shutdown(Shutdown::Write).unwrap();
        let mut response=Vec::new();stream.read_to_end(&mut response).unwrap();assert!(response.is_empty());
        assert!(f.run(&["status"]).contains("running:"));
    }
    f.run(&["kill-server"]);
}

#[test]
fn interactive_commands_autostart_but_deny_without_trust() {
    let f=Fixture::new();
    for args in [&["pair"][..],&["pair","--code-entry","host"][..],&["auth"][..]] {
        let output=f.cmd().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("device trust is not configured"));
    }
    assert!(f.run(&["status"]).contains("network authentication disabled"));
    assert_eq!(f.run(&["devices"]).trim(),"List of devices attached");
    assert!(!f.data().parent().unwrap().join("operation.sock").exists());
}

#[test]
fn hardware_test_cli_isolated_and_unconfigured_fail_closed(){
    let f=Fixture::new();
    assert!(f.run(&["--hardware-test","status"]).contains("stopped"));assert!(!f.0.exists());
    f.run(&["devices"]);f.run(&["--hardware-test","devices"]);
    let test=f.0.join("rba/hardware-test-v2/instance");let normal=f.data();
    assert_ne!(fs::read(test.join("host-key.pk8")).unwrap(),fs::read(normal.join("host-key.pk8")).unwrap());
    assert!(f.run(&["--hardware-test","status"]).contains("hardware test"));
    assert!(f.run(&["status"]).contains("network authentication disabled"));
    assert!(!f.cmd().args(["--hardware-test","pair"]).output().unwrap().status.success());
    let signer="44".repeat(32);
    assert!(!f.cmd().args(["--hardware-test","configure","--signer",&signer,"--listen","0.0.0.0"]).output().unwrap().status.success());
    f.run(&["--hardware-test","kill-server"]);assert!(f.run(&["status"]).contains("running:"));
    assert!(!f.cmd().arg("--check-candidate").arg(test.parent().unwrap()).output().unwrap().status.success());
    assert!(!f.cmd().args(["configure","--signer",&signer,"--listen","192.168.1.2"]).output().unwrap().status.success());
    assert!(!test.parent().unwrap().join("operation.sock").exists());
}
