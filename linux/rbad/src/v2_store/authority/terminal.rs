//! Exact post-commit wire receipt. A denied connection never becomes a live
//! peer again. Only the owning transport may consume the frame; there is no
//! API to supply replacement bytes or restore ordinary I/O.
use super::*;
use rba_protocol::v2_message::{Kind,Message};
use zeroize::Zeroizing;
const WRITE_WINDOW:Duration=Duration::from_secs(5);
const MAX_FRAME:usize=1024;

pub(super) struct Terminal {
    pub(super) credential:Id,
    pub(super) owner:Option<Id>,
    pub(super) issued_wall:i64,
    pub(super) until_wall:i64,
    pub(super) issued_mono:Instant,
    pub(super) until_mono:Instant,
    listener:Listener,
    frame:Option<Zeroizing<Vec<u8>>>, // None once irreversibly claimed
}
impl Authority {
    /// Called only by successful, consumed authority operations, after denial.
    /// A late receipt does not undo a committed operation. Use a fresh,
    /// authenticated recovery channel where the protocol provides recovery.
    pub(super) fn arm_terminal(&mut self,conn:ConnectionId,credential:Id,owner:Option<Id>,message:&Message,now:i64,mono:Instant,limit:Option<(i64,Instant)>)->Result<()> {
        let listener=match message.kind(){
            Kind::EnrollReceipt=>Listener::Enrollment,
            Kind::AuthResult|Kind::RevokeReceipt|Kind::EnrollStatusResult|Kind::PolicyReceipt=>Listener::Production,
            _=>return Err(Error::Denied),
        };
        if !self.resources.terminal_slot(conn,listener)||self.terminals.contains_key(&conn){return Err(Error::Denied)}
        self.trust_check(now,mono)?;check_clock(&self.store.db,now)?;
        let mut until_wall=now.checked_add(WRITE_WINDOW.as_secs() as i64).ok_or(Error::Clock)?;
        let mut until_mono=mono.checked_add(WRITE_WINDOW).ok_or(Error::Clock)?;
        if let Some((w,m))=limit {until_wall=until_wall.min(w);until_mono=until_mono.min(m);}
        if until_wall<=now||until_mono<=mono{return Err(Error::Clock)}
        let frame=Zeroizing::new(message.encode().map_err(|_|Error::Invalid)?);
        if frame.len()>MAX_FRAME{return Err(Error::Invalid)}
        if Instant::now()>=until_mono{return Err(Error::Clock)}
        self.terminals.insert(conn,Terminal{credential,owner,issued_wall:now,until_wall,issued_mono:mono,until_mono,listener,frame:Some(frame)});
        Ok(())
    }
    fn terminal_valid(&self,conn:ConnectionId,now:i64,mono:Instant)->bool{
        self.terminals.get(&conn).is_some_and(|t|self.resources.terminal_slot(conn,t.listener) &&
            t.issued_wall<=now && now<t.until_wall && t.issued_mono<=mono && mono<t.until_mono)
            && self.wall_high.is_none_or(|w|now>=w) && self.trust_check(now,mono).is_ok() && check_clock(&self.store.db,now).is_ok()
            && self.terminals.get(&conn).is_some_and(|t|Instant::now()<t.until_mono)
    }
    pub(crate) fn claim_terminal(&mut self,conn:ConnectionId,now:i64,mono:Instant)->Result<(Zeroizing<Vec<u8>>,Instant)>{
        if !self.terminal_valid(conn,now,mono){self.deny_connection(conn);return Err(Error::Denied)}
        let t=self.terminals.get_mut(&conn).ok_or(Error::Denied)?;
        let frame=t.frame.take().ok_or(Error::Denied)?;
        Ok((frame,t.until_mono))
    }
    /// The socket retains its original resource slot. No normal read or write
    /// path calls this method, and it is valid only once the frame is claimed.
    pub(crate) fn terminal_writing(&self,conn:ConnectionId,now:i64,mono:Instant)->bool{
        self.terminal_valid(conn,now,mono) && self.terminals.get(&conn).is_some_and(|t|t.frame.is_none())
    }
}
