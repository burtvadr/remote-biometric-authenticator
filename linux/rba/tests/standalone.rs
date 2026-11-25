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
    fn drop(&mut self){let _=self.cmd().arg("stop").stdout(Stdio::null()).stderr(Stdio::null()).status();let _=fs::remove_dir_all(&self.0);}
}
#[test]
fn zero_config_concurrent_start_and_restart_preserve_identity(){
    let f=Fixture::new();
    let mut a=f.cmd().stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let b=f.cmd().arg("start").output().unwrap();
    assert!(a.wait().unwrap().success());assert!(b.status.success());
    assert!(f.run(&["status"]).contains("network authentication disabled"));
    let data=f.data();let key=fs::read(data.join("host-key.pk8")).unwrap();
    let settings=fs::read(data.join("candidate.json")).unwrap();
    let cert=fs::read(data.join("host-cert.der")).unwrap();
    assert!(data.join("state/state.sqlite3").is_file());
    let outer=data.parent().unwrap();
    let duplicate=f.cmd().arg("--run-candidate").arg(outer).output().unwrap();
    assert!(!duplicate.status.success());
    f.run(&["stop"]);
    assert!(!f.cmd().arg("status").output().unwrap().status.success());
    f.run(&[]);
    assert_eq!(fs::read(data.join("host-key.pk8")).unwrap(),key);
    assert_eq!(fs::read(data.join("candidate.json")).unwrap(),settings);
    assert_eq!(fs::read(data.join("host-cert.der")).unwrap(),cert);
    f.run(&["stop"]);
}
