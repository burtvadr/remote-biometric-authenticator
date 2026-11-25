//! Authentication rendezvous. The local adapter admits one request before a
//! device connects. A remote wait channel never creates a local operation.
use super::*;
use crate::v2_store::authority::LocalIntent;
use tokio::sync::watch;

struct Pending {
    local: LocalLink,
    request: Id,
    deadline: Deadline,
    source: String,
    detail: String,
}

pub(crate) struct AuthScheduler {
    authority: Owner,
    pending: Mutex<BTreeMap<Id, Pending>>,
    changes: watch::Sender<()>,
}
impl AuthScheduler {
    pub(crate) fn new(authority: Owner) -> Self {
        Self { authority, pending: Mutex::new(BTreeMap::new()), changes: watch::channel(()).0 }
    }
    fn prune(&self, queue: &mut BTreeMap<Id, Pending>) -> Result<()> {
        let now = Deadline::now();
        let mut a = self.authority.lock().map_err(|_| Error::State)?;
        queue.retain(|_, p| {
            if p.local.tx.is_closed() || now >= p.deadline {
                a.cancel_local(p.local.owner, p.request); false
            } else { true }
        });
        Ok(())
    }
    /// Only the verified local adapter calls this. Its receiver owns the
    /// original interaction, and must be dropped on IPC disconnect. No local
    /// identity, source or detail comes from a network request.
    pub(crate) fn submit(&self, intent: LocalIntent, credential: Id, seconds: u64,
                         source: String, detail: String) -> Result<(Id, mpsc::Receiver<LocalEvent>)> {
        if source.is_empty() || source.len()>64 || detail.is_empty() || detail.len()>256 {return Err(Error::Invalid);}
        let mut queue = self.pending.lock().map_err(|_| Error::State)?;
        self.prune(&mut queue)?;
        if queue.len() >= 32 || queue.contains_key(&credential) { return Err(Error::Denied); }
        let (local, rx) = LocalLink::new(intent.owner, intent.interaction)?;
        let (now, mono) = clock()?;
        let request = locked(&self.authority, |a| a.begin(intent, credential, seconds, now, mono))?;
        let deadline = Deadline::from_std(mono + Duration::from_secs(seconds));
        queue.insert(credential, Pending { local, request, deadline, source, detail });
        self.changes.send_replace(());
        Ok((request, rx))
    }
    fn take(&self, credential: Id) -> Result<Option<Pending>> {
        let mut queue = self.pending.lock().map_err(|_| Error::State)?;
        self.prune(&mut queue)?;
        Ok(queue.remove(&credential))
    }
    fn cancel(&self, p: &Pending) {
        if let Ok(mut a) = self.authority.lock() { a.cancel_local(p.local.owner, p.request); }
    }
    /// Called only on an authenticated wait channel. While idle, peer data
    /// or EOF closes it; never interpret remote data as a scheduling request.
    /// The 25s wait fits the 30s normative idle deadline. Once selected,
    /// dispatch uses the original local deadline, not a new allowance.
    pub(crate) async fn serve(&self, mut channel: Channel, signer: &SigningKey) -> Result<ReceiptDelivery> {
        if !Arc::ptr_eq(&self.authority, &channel.stream.get_ref().0.owner)
            || channel.purpose() != Some(Purpose::Authentication) || channel.access != Some(PeerState::Active) {
            return Err(Error::Denied);
        }
        let credential = channel.credential().ok_or(Error::Denied)?;
        let until = Deadline::now() + Duration::from_secs(25);
        let mut changes = self.changes.subscribe();
        loop {
            if Deadline::now() >= until { return Err(Error::Denied); }
            if let Some(p) = self.take(credential)? {
                let route = locked(&self.authority, |a| a.auth_route(p.local.owner, p.local.interaction, p.request, channel.id()));
                if route.is_err() || p.local.live(p.deadline).is_err() { self.cancel(&p); return Err(Error::Denied); }
                let id = p.local.owner; let request = p.request;
                // Also cancel if the driver is dropped before it installs its
                // own guard. The owner ID is unique to this IPC interaction.
                let _guard = LocalGuard { authority: self.authority.clone(), owner: id };
                return channel.authenticate(p.local, request, signer, &p.source, &p.detail).await;
            }
            let mut unexpected = [0u8; 1];
            tokio::select! {
                biased;
                _ = channel.stream.read(&mut unexpected) => return Err(Error::Denied),
                _ = tokio::time::sleep_until(until) => return Err(Error::Denied),
                result = changes.changed() => { result.map_err(|_| Error::State)?; }
            }
        }
    }
}
impl Drop for AuthScheduler {
    fn drop(&mut self) {
        if let (Ok(queue), Ok(mut a)) = (self.pending.get_mut(), self.authority.lock()) {
            for p in queue.values() { a.cancel_local(p.local.owner, p.request); }
        }
    }
}
