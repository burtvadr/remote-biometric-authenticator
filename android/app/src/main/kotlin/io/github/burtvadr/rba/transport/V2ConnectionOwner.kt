package io.github.burtvadr.rba.transport

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import io.github.burtvadr.rba.keystore.V2HardwareKeys
import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Authentication
import io.github.burtvadr.rba.protocol.V2DevicePolicy
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.protocol.V2Message
import io.github.burtvadr.rba.protocol.V2PolicySync
import io.github.burtvadr.rba.protocol.V2Revocation
import io.github.burtvadr.rba.session.NativeEnrollment
import io.github.burtvadr.rba.session.V2DeviceStore
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import java.net.InetSocketAddress

/** Android operation owner. Call from an explicitly selected local operation,
 * not from discovery or a remote message. One operation process-wide; its
 * structured coroutine scope owns the transport, state and biometric prompt.
 * The UI adapter must render exact supplied facts, await actual user input,
 * and dismiss on cancellation. No production UI/service entry point yet. */
internal object V2ConnectionOwner {
    interface Ui {
        val activity:FragmentActivity
        suspend fun enterNumber(core:Cbor.Value.Map):String?
        suspend fun enterPairingCode():ByteArray?
        suspend fun displayPairingCode(code:ByteArray):Boolean
        suspend fun reviewEnrollment(facts:V2Enrollment.Confirmation):ByteArray?
        suspend fun reviewCleanup(credentials:List<ByteArray>):Boolean
        suspend fun reviewInitialPolicy(offer:V2Message.Message,offerHash:ByteArray):ByteArray?
        suspend fun reviewPolicy(offer:V2Message.Message,digest:ByteArray):ByteArray?
    }
    private val exclusive=Mutex()
    private fun wall()=System.currentTimeMillis()/1000
    private fun mono()=SystemClock.elapsedRealtime()
    private suspend fun <T> owned(work:suspend CoroutineScope.()->T):T {
        check(exclusive.tryLock()){ "Another V2 operation is active" }
        try{return withContext(Dispatchers.IO){coroutineScope{work()}}}
        finally{exclusive.unlock()}
    }
    private fun wire(scope:CoroutineScope,c:V2TlsClient.Channel)=V2OperationWire(scope,object:V2OperationWire.Link{
        override fun read(deadline:Long)=c.read(deadline)
        override fun write(message:V2Message.Message,deadline:Long)=c.write(message,deadline)
        override fun close()=c.close()
    },::mono)
    private suspend fun <T> onUi(ui:Ui,work:suspend ()->T):T=withContext(Dispatchers.Main.immediate){
        check(ui.activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))
        coroutineScope {
            val job=currentCoroutineContext().job
            val observer=object:DefaultLifecycleObserver{
                override fun onStop(owner:LifecycleOwner){job.cancel(CancellationException("Activity stopped"))}
            }
            ui.activity.lifecycle.addObserver(observer)
            try{ensureActive();work()}finally{ui.activity.lifecycle.removeObserver(observer)}
        }
    }
    /** Actual Android CryptoObject is bound to the state machine's transcript.
     * Cancellation invalidates the operation, including late OS callbacks. */
    private suspend fun biometric(context:Context,ui:Ui,keys:V2HardwareKeys.Credential,transcript:ByteArray):ByteArray {
        val op=keys.prepareBiometric(context,transcript)
        return onUi(ui){suspendCancellableCoroutine{c->
            val handler=Handler(Looper.getMainLooper())
            c.invokeOnCancellation { if(Looper.myLooper()==Looper.getMainLooper())op.cancel() else handler.post{op.cancel()} }
            if(c.isActive)op.authenticate(ui.activity,"RBA authentication","Strong biometric required","Approve the operation you just reviewed."){result->c.resumeWith(result)}
        }}
    }
    /** Re-read the durable policy at every sensitive transition. Enrollment
     * records and their recovery receipts remain immutable. */
    private fun policy(store:V2DeviceStore,record:V2Enrollment.Pending):V2DevicePolicy {
        val current=checkNotNull(store.active(record.credentialId()))
        check(current.encode().contentEquals(record.encode()))
        return checkNotNull(store.policySnapshot(record.credentialId()).policy()){ "No locally approved grant" }
    }
    suspend fun synchronizePolicy(store:V2DeviceStore,address:InetSocketAddress,credential:ByteArray,ui:Ui):Boolean=owned {
        val snapshot=store.policySnapshot(credential.copyOf())
        val channel=V2TlsClient.Channel.enrolled(address,store,snapshot.credential(),V2TlsClient.EnrolledPurpose.POLICY)
        wire(this,channel).use{w->
            val until=mono()+60000
            val sync=V2PolicySync(snapshot,channel.session().sessionId(),until)
            try {
                val offer=w.receive(V2Message.Kind.POLICYOFFER,minOf(until,mono()+30000))
                val digest=sync.offer(offer,mono())
                val consent=w.interaction(until){onUi(ui){ui.reviewPolicy(offer,digest.copyOf())}}
                w.send(sync.decision(consent,mono()),until)
                if(consent==null)return@owned false
                sync.receipt(w.receive(V2Message.Kind.POLICYRECEIPT,until),mono()){old,next->store.commitPolicy(snapshot.credential(),old,next)}
                true
            } finally {sync.cancel()}
        }
    }
    suspend fun authenticate(context:Context,store:V2DeviceStore,address:InetSocketAddress,credential:ByteArray,ui:Ui):Boolean =
        authenticate(context,store,address,credential) { ui }
    /** Background wait is allowed to request a foreground UI only after the
     * exact signed AUTH_REQUEST passes all policy and channel checks. The UI
     * handoff shares the original operation deadline and live socket. */
    suspend fun authenticate(context:Context,store:V2DeviceStore,address:InetSocketAddress,credential:ByteArray,onConnected:()->Unit={},awaitUi:suspend (Long)->Ui?):Boolean=owned {
        val record=checkNotNull(store.active(credential.copyOf()))
        policy(store,record)
        val keys=V2HardwareKeys.load(record.credentialId(),record.transportKey(),record.biometricKey())
        val channel=V2TlsClient.Channel.enrolled(address,store,record.credentialId(),V2TlsClient.EnrolledPurpose.AUTHENTICATION)
        wire(this,channel).use{w->
            val s=channel.session()
            onConnected()
            val auth=V2Authentication(s.hostId(),s.credentialId(),s.sessionId(),s.hostNonce(),s.deviceNonce(),s.exporter(),s.hostKey(),keys.biometricPoint())
            try{
                val request=w.receive(V2Message.Kind.AUTHREQUEST,mono()+30000)
                val core=auth.acceptRequest(request,policy(store,record),wall(),mono())
                val until=auth.operationDeadline()
                var selectedUi:Ui?=null
                val digits=w.interaction(until){
                    val foreground=awaitUi(until)?:return@interaction null
                    selectedUi=foreground
                    onUi(foreground){foreground.enterNumber(core)}
                }
                if(digits==null){auth.cancel()?.let{w.send(it,until)};return@owned false}
                val entry=auth.enterNumber(digits,policy(store,record),wall(),mono())
                w.send(entry,until)
                val matched=w.receive(V2Message.Kind.MATCHED,until)
                val transcript=auth.acceptMatch(matched,policy(store,record),wall(),mono())
                val proof=w.interaction(until){biometric(context,checkNotNull(selectedUi),keys,transcript)}
                val response=auth.completeBiometric(proof,policy(store,record),wall(),mono())
                w.send(response,until)
                // Informational only. The host independently owns OS success.
                auth.acceptResult(w.receive(V2Message.Kind.AUTHRESULT,until),wall(),mono())
            }finally{auth.invalidate()}
        }
    }
    /** Cleanup IDs must be explicitly selected locally; only records already
     * durably denied by beginRevocation() may supply an old token. */
    suspend fun enroll(context:Context,store:V2DeviceStore,address:InetSocketAddress,ui:Ui,cleanupCredentials:List<ByteArray> = emptyList()):ByteArray=owned {
        check(cleanupCredentials.size<=32)
        val cleanup=cleanupCredentials.map{store.revoking(it.copyOf())}
        check(cleanup.map{Cbor.bytes(it.credentialId())}.toSet().size==cleanup.size)
        val staging=object:V2Enrollment.PendingStore{
            override fun stage(record:ByteArray)=store.stageWithCleanup(record,cleanup)
            override fun activate(expectedPending:ByteArray)=store.activate(expectedPending)
        }
        val channel=V2TlsClient.Channel.provisional(address)
        wire(this,channel).use{w->
            channel.enrollment(NativeEnrollment.v2Pake).use{enrollment->
                var generated:V2HardwareKeys.Credential?=null
                try{
                    val start=w.receive(V2Message.Kind.ENROLLSTART,mono()+30000)
                    val challenges=enrollment.acceptStart(start,wall(),mono())
                    val until=enrollment.operationDeadline()
                    val keys=store.generateEnrollmentKeys(context,challenges);generated=keys
                    val direction=(start.payload()["direction"] as Cbor.Value.Uint).value
                    val entered=if(direction==0L)w.interaction(until){onUi(ui){ui.enterPairingCode()}}else null
                    if(direction==0L&&entered==null){enrollment.cancel()?.let{w.send(it,until)};error("Enrollment declined")}
                    val share=try{enrollment.share(keys.id(),keys.transportPoint(),keys.biometricPoint(),entered,wall(),mono())}finally{entered?.fill(0)}
                    share.displayCode?.let{code->
                        val shown=try{w.interaction(until){onUi(ui){ui.displayPairingCode(code)}}}finally{code.fill(0)}
                        if(!shown){enrollment.cancel()?.let{w.send(it,until)};error("Enrollment declined")}
                    }
                    w.send(share.message,until)
                    val confirmation=enrollment.confirm(w.receive(V2Message.Kind.ENROLLCONFIRMA,until),wall(),mono())
                    w.send(confirmation.message,until)
                    val approved=w.interaction(until){onUi(ui){ui.reviewEnrollment(confirmation)}}
                    if(approved==null){enrollment.cancel()?.let{w.send(it,until)};error("Enrollment declined")}
                    if(cleanup.isNotEmpty()&&!w.interaction(until){onUi(ui){ui.reviewCleanup(cleanup.map{it.credentialId()})}}){
                        enrollment.cancel()?.let{w.send(it,until)};error("Cleanup declined")
                    }
                    val proofs=enrollment.approve(approved,wall(),mono())
                    val biometric=w.interaction(until){biometric(context,ui,keys,proofs.biometric)}
                    val evidence=enrollment.evidence(keys.transportChain(),keys.biometricChain(),keys.transportProof(proofs),biometric,cleanup,wall(),mono())
                    w.send(evidence,until)
                    val offer=w.receive(V2Message.Kind.ENROLLOFFER,until)
                    val hash=enrollment.acceptOffer(offer,wall(),mono())
                    val accepted=w.interaction(until){onUi(ui){ui.reviewInitialPolicy(offer,hash.copyOf())}}
                    if(accepted==null){enrollment.cancel()?.let{w.send(it,until)};error("Enrollment declined")}
                    val staged=enrollment.stageOffer(accepted,staging,wall(),mono())
                    w.send(staged,until)
                    enrollment.receipt(w.receive(V2Message.Kind.ENROLLRECEIPT,until),staging,wall(),mono())
                    keys.id()
                }finally{
                    // Do not delete keys on lost receipt, uncertain SQLite
                    // commit, or cancellation after durable staging.
                    generated?.let{store.discardIfUnrecorded(it)}
                }
            }
        }
    }
    /** Explicit local revoke or retry. A missing receipt never restores local
     * permission. A persisted receipt needs only local cleanup on restart. */
    suspend fun revoke(store:V2DeviceStore,address:InetSocketAddress,credential:ByteArray):Unit=owned {
        val id=credential.copyOf()
        store.beginRevocation(id)
        if(!store.revocationAcknowledged(id)){
            val record=store.revoking(id)
            val channel=V2TlsClient.Channel.revocation(address,store,id)
            wire(this,channel).use{w->
                val s=channel.session();val started=mono();val startedWall=wall()
                val revocation=V2Revocation(record,s.hostId(),s.hostKey(),s.credentialId(),channel.localTransportKey(),s.sessionId(),startedWall,started)
                try{
                    val until=revocation.deadline()
                    w.send(revocation.request(wall(),mono()),until)
                    revocation.receipt(w.receive(V2Message.Kind.REVOKERECEIPT,until),wall(),mono()){
                        store.acknowledgeRevocation(id,record.encode())
                    }
                }finally{revocation.cancel()}
            }
        }
        store.finishRevocationCleanup(id)
    }
    /** Concrete runtime startup must call this before launching network/UI
     * operation owners. It opens the canonical store, never a selected file. */
    suspend fun reclaimAtStartup(context:Context):Unit=owned {
        V2DeviceStore.openOrInitializeFresh(context).use{it.reclaimAtExclusiveStartup()}
    }
    /** Separate locally chosen pending recovery operation; never routes auth. */
    suspend fun recover(store:V2DeviceStore,address:InetSocketAddress,credential:ByteArray):Unit=owned {
        val record=checkNotNull(store.pending(credential.copyOf()))
        val channel=V2TlsClient.Channel.enrolled(address,store,record.credentialId(),V2TlsClient.EnrolledPurpose.RECOVERY)
        wire(this,channel).use{w->
            val s=channel.session()
            val startedWall=wall();val startedMono=mono()
            val recovery=record.recover(s.hostId(),s.hostKey(),s.credentialId(),channel.localTransportKey(),s.sessionId(),startedWall,startedMono)
            val until=Math.addExact(startedMono,minOf(60L,record.recoverUntil()-startedWall)*1000L)
            try{
                w.send(recovery.request(),until)
                recovery.accept(w.receive(V2Message.Kind.ENROLLSTATUSRESULT,until),store,wall(),mono())
            }finally{recovery.cancel()}
        }
    }
}
