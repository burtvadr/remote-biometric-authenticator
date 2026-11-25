//! Current-user bootstrap; never installs a service or elevates privileges.
use super::*;
use std::{fs::{self,DirBuilder,File},io::Write,os::{fd::AsRawFd,unix::fs::{DirBuilderExt,MetadataExt}},path::{Component,PathBuf}};

fn uid()->u32{unsafe{libc::geteuid()}}
fn absent(path:&Path)->Result<bool>{
    match fs::symlink_metadata(path){Ok(_)=>Ok(false),Err(e) if e.kind()==io::ErrorKind::NotFound=>Ok(true),Err(e)=>Err(e.into())}
}
fn mkdir(path:&Path)->Result<()>{
    match DirBuilder::new().mode(0o700).create(path){Ok(())=>Ok(()),Err(e) if e.kind()==io::ErrorKind::AlreadyExists=>Ok(()),Err(e)=>Err(e.into())}
}
/// Validate every component before using it. A user daemon does not share a
/// privileged store; paths with symlinks or writable-by-others ancestors fail.
pub(super) fn create_root(dir:&Path)->Result<()> {
    if !dir.is_absolute(){return Err(Error::Invalid)}
    let mut path=PathBuf::from("/");
    for c in dir.components(){
        match c{Component::RootDir=>continue,Component::Normal(n)=>path.push(n),_=>return Err(Error::Invalid)}
        if absent(&path)?{mkdir(&path)?;}
        let m=fs::symlink_metadata(&path)?;
        if !m.is_dir()||(m.uid()!=0&&m.uid()!=uid())||m.mode()&0o022!=0{return Err(Error::Denied)}
    }
    private_dir(dir,uid())
}
fn open_lock(dir:&Path,create:bool)->Result<File>{
    private_dir(dir,uid())?;
    let path=dir.join("daemon.lock");
    let file=OpenOptions::new().read(true).write(true).create(create).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&path)?;
    private_regular(&path,uid())?;
    let m=file.metadata()?;let p=fs::symlink_metadata(&path)?;
    if !m.is_file()||m.uid()!=uid()||m.mode()&0o7777!=0o600||m.nlink()!=1||m.ino()!=p.ino()||m.dev()!=p.dev(){return Err(Error::Denied)}
    if unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{return Err(io::Error::last_os_error().into())}
    Ok(file)
}
pub(super) fn lock(dir:&Path)->Result<File>{create_root(dir)?;open_lock(dir,true)}
pub(super) fn lock_existing(dir:&Path)->Result<File>{open_lock(dir,false)}
fn write_private(path:&Path,bytes:&[u8])->Result<()> {
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)?;
    f.write_all(bytes)?;f.sync_all()?;Ok(())
}
fn verify(data:&Path)->Result<()> {
    let m=load(data)?;Store::open(&data.join("state"),m.host)?;Ok(())
}
/// Requires the outer daemon lock. Publish all files and SQLite together by
/// renaming a completed sibling directory. Never replace an existing identity.
pub(super) fn ensure(dir:&Path)->Result<PathBuf>{
    let data=dir.join("instance");let pending=dir.join("bootstrap.pending");
    if !absent(&data)?{
        if !absent(&pending)?{return Err(Error::State)}
        verify(&data)?;return Ok(data)
    }
    // Do not overwrite legacy layouts, unknown material or partial published state.
    for item in fs::read_dir(dir)?{
        let name=item?.file_name();
        if !["daemon.lock","daemon.log","bootstrap.pending"].iter().any(|n|name==std::ffi::OsStr::new(n)){return Err(Error::State)}
    }
    if absent(&pending)?{
        mkdir(&pending)?;private_dir(&pending,uid())?;
        let host=super::super::random::<16>()?;
        let cert=rcgen::generate_simple_self_signed(vec!["rbad".into()]).map_err(|_|Error::State)?;
        let key=Zeroizing::new(cert.key_pair.serialize_der());
        let s=Settings{host_id:hex::encode(host),bind:"127.0.0.1:8765".parse().map_err(|_|Error::State)?,enrollment_bind:"127.0.0.1:8766".parse().map_err(|_|Error::State)?,release_signer:None,minimum_app_version:0,minimum_os_version:0,minimum_os_patch:0,minimum_vendor_patch:0,minimum_boot_patch:0};
        write_private(&pending.join("candidate.json"),&serde_json::to_vec_pretty(&s).map_err(|_|Error::State)?)?;
        write_private(&pending.join("host-key.pk8"),key.as_slice())?;
        write_private(&pending.join("host-cert.der"),cert.cert.der().as_ref())?;
        mkdir(&pending.join("state"))?;
        Store::initialize(&pending.join("state"),host,wall()?)?;
        File::open(&pending)?.sync_all()?;
    }
    // A complete interrupted staging directory can be published on retry;
    // incomplete staging is preserved and fails closed for diagnosis.
    verify(&pending)?;
    fs::rename(&pending,&data)?;
    File::open(dir)?.sync_all()?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new()->Self{
            let base=PathBuf::from(std::env::var_os("HOME").expect("HOME for owner-only tests"));
            let p=base.join(format!(".rba-bootstrap-test-{}",hex::encode(super::super::super::random::<16>().unwrap())));
            Self(p)
        }
    }
    impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
    #[test] fn first_run_is_idempotent_and_exclusive(){
        let f=Fixture::new();let lock1=lock(&f.0).unwrap();
        assert!(lock(&f.0).is_err());
        let d=ensure(&f.0).unwrap();let key=fs::read(d.join("host-key.pk8")).unwrap();
        let id=load(&d).unwrap().host;assert!(load(&d).unwrap().policy.is_none());
        drop(lock1);let _lock2=lock(&f.0).unwrap();assert_eq!(ensure(&f.0).unwrap(),d);
        assert_eq!(load(&d).unwrap().host,id);assert_eq!(fs::read(d.join("host-key.pk8")).unwrap(),key);
        fs::remove_file(d.join("host-cert.der")).unwrap();assert!(ensure(&f.0).is_err());
        assert_eq!(fs::read(d.join("host-key.pk8")).unwrap(),key);
    }
    #[test] fn incomplete_bootstrap_is_preserved(){
        let f=Fixture::new();let _lock=lock(&f.0).unwrap();let p=f.0.join("bootstrap.pending");mkdir(&p).unwrap();
        write_private(&p.join("host-key.pk8"),b"partial").unwrap();
        assert!(ensure(&f.0).is_err());assert_eq!(fs::read(p.join("host-key.pk8")).unwrap(),b"partial");
        assert!(absent(&f.0.join("instance")).unwrap());
    }
}
