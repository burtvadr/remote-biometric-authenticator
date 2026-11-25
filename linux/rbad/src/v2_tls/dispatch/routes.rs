//! Local administrative routing for the V2-only runtime. The verified B.4 IPC
//! adapter is the sole intended caller. No network-driven admission or user
//! identity inference. Local receiver teardown cancels the original operation.
use super::*;
use tokio::net::TcpListener;
use std::net::SocketAddr;

struct PolicyRoute {
    local: LocalLink,
    caller: Principal,
    expected: i64,
    grants: Vec<Grant>,
    deadline: Deadline,
    result: oneshot::Sender<Result<(bool,ReceiptDelivery)>>,
}
pub(crate) struct AdministrativeRoutes {
    authority: Owner,
    policy: Mutex<BTreeMap<Id,PolicyRoute>>,
}
impl AdministrativeRoutes {
    pub(crate) fn new(authority:Owner)->Self { Self{authority,policy:Mutex::new(BTreeMap::new())} }
    fn prune(routes:&mut BTreeMap<Id,PolicyRoute>) {
        routes.retain(|_,r|r.local.live(r.deadline).is_ok() && !r.result.is_closed());
    }
    /// No automatic current-policy offer: even recovery has an explicit local
    /// owner. The local adapter verifies the caller and selects all arguments.
    pub(crate) fn queue_policy(&self,local:LocalLink,credential:Id,caller:Principal,expected:i64,grants:Vec<Grant>,deadline:Deadline)->Result<oneshot::Receiver<Result<(bool,ReceiptDelivery)>>> {
        local.live(deadline)?;
        if credential==[0;16]||expected<1||grants.len()>32||deadline>Deadline::now()+Duration::from_secs(60){return Err(Error::Denied)}
        let mut routes=self.policy.lock().map_err(|_|Error::State)?;Self::prune(&mut routes);
        if routes.len()>=32||routes.contains_key(&credential)||routes.values().any(|r|r.local.owner==local.owner){return Err(Error::Denied)}
        let (result,rx)=oneshot::channel();
        routes.insert(credential,PolicyRoute{local,caller,expected,grants,deadline,result});Ok(rx)
    }
    pub(crate) fn tick(&self)->Result<()> {
        let mut routes=self.policy.lock().map_err(|_|Error::State)?;Self::prune(&mut routes);Ok(())
    }
    pub(crate) async fn policy(&self,channel:Channel)->Result<()> {
        if !Arc::ptr_eq(&self.authority,&channel.stream.get_ref().0.owner)||channel.purpose()!=Some(Purpose::Policy){return Err(Error::Denied)}
        let credential=channel.credential().ok_or(Error::Denied)?;
        let route={let mut routes=self.policy.lock().map_err(|_|Error::State)?;Self::prune(&mut routes);routes.remove(&credential).ok_or(Error::Denied)?};
        route.local.live(route.deadline)?;
        let _guard=LocalGuard{authority:self.authority.clone(),owner:route.local.owner};
        let PolicyRoute{local,caller,expected,grants,deadline,mut result}=route;
        let outcome=tokio::select!{
            biased;
            _=result.closed()=>return Err(Error::Denied),
            out=channel.synchronize_policy(local,credential,caller,expected,&grants,deadline)=>out,
        };
        result.send(outcome).map_err(|_|Error::Denied)?;Ok(())
    }
    /// Open an enrollment listener only for a locally admitted pairing. Bind
    /// address comes from protected runtime configuration, not IPC or the peer.
    /// Closing the local receiver or expiring the original pairing ends it.
    pub(crate) async fn enroll(&self,identity:&Identity,host:Id,address:SocketAddr,local:LocalLink,caller:Principal,direction:EntryDirection)->Result<ReceiptDelivery>{
        if address.port()==0{return Err(Error::Denied)}
        let (now,mono)=clock()?;
        let deadline=Deadline::from_std(mono+Duration::from_secs(120));
        local.live(deadline)?;
        let pairing=locked(&self.authority,|a|a.begin_pairing(local.owner,caller,now,mono))?;
        let _guard=LocalGuard{authority:self.authority.clone(),owner:local.owner};
        let listener=local.wait(deadline,async{Ok(TcpListener::bind(address).await?)}).await?;
        let address=listener.local_addr()?;
        let advertisement=super::super::discovery::Announcement::publish(address,host,&identity.point,super::super::discovery::Role::Enrollment,Some(pairing));
        local.ask(deadline, |shown| LocalEvent::EnrollmentListening { address, shown }).await?;
        let (tcp,_)=local.wait(deadline,async{Ok(listener.accept().await?)}).await?;
        drop(advertisement);
        drop(listener); // exactly one transport per admitted pairing
        let channel=local.wait(deadline,accept(tcp,self.authority.clone(),identity,Listener::Enrollment)).await?;
        channel.enroll(local,pairing,direction).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn administrative_queue_is_one_shot_and_prunes_closed_owner(){
        let key=|n:u8| -> [u8;65] { p256::ecdsa::SigningKey::from_slice(&[n;32]).unwrap().verifying_key().to_encoded_point(false).as_bytes().try_into().unwrap() };
        let authority=Arc::new(Mutex::new(Authority::new(crate::v2_store::tls_test_store(&key(1),&key(2),wall().unwrap()))));
        let routes=AdministrativeRoutes::new(authority);
        let caller=Principal{id:[1;16],uid:1000,name:"user1000".into(),generation:[2;16]};
        let (local,rx)=LocalLink::new([1;16],[2;16]).unwrap();
        let deadline=Deadline::now()+Duration::from_secs(30);
        let _result=routes.queue_policy(local,[4;16],caller.clone(),1,vec![],deadline).unwrap();
        let (other,_rx)=LocalLink::new([4;16],[5;16]).unwrap();
        assert!(routes.queue_policy(other,[4;16],caller.clone(),1,vec![],deadline).is_err());
        drop(rx);routes.tick().unwrap();assert!(routes.policy.lock().unwrap().is_empty());
        let (late,_rx)=LocalLink::new([6;16],[7;16]).unwrap();
        assert!(routes.queue_policy(late,[4;16],caller,1,vec![],Deadline::now()).is_err());
    }
}
