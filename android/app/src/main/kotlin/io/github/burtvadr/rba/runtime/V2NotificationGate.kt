package io.github.burtvadr.rba.runtime

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job

/** One nonpersistent foreground handoff. A notification identifier is only
 * a rendezvous locator; it never constitutes approval or biometric evidence. */
internal class V2NotificationGate<T:Any>(private val now:()->Long) {
    internal class Ticket<T:Any>(val token:String,val deadline:Long,val job:Job) {
        internal val response=CompletableDeferred<T>()
        internal var attached:T?=null
        suspend fun await():T=response.await()
    }
    private var live:Ticket<T>?=null
    @Synchronized fun open(token:String,deadline:Long,job:Job):Ticket<T> {
        check(live==null && token.isNotEmpty() && deadline-now() in 1..60000 && job.isActive)
        return Ticket<T>(token,deadline,job).also{live=it}
    }
    @Synchronized fun attach(token:String,value:T):Boolean {
        val ticket=live?:return false
        if(ticket.token!=token || now()>=ticket.deadline || !ticket.job.isActive)return false
        if(!ticket.response.complete(value))return false
        ticket.attached=value;return true
    }
    @Synchronized fun release(ticket:Ticket<T>):T? {
        if(live===ticket){live=null;ticket.response.cancel()}
        // Return only the activity attached to THIS operation, including when
        // stop/abandon already removed the live slot. Never close a new UI.
        return ticket.attached.also{ticket.attached=null}
    }
    @Synchronized fun abandon(token:String) {
        val ticket=live?:return
        if(ticket.token!=token || !ticket.response.isCompleted)return
        live=null;ticket.response.cancel();ticket.job.cancel()
    }
    @Synchronized fun stop() {
        val ticket=live?:return
        live=null;ticket.response.cancel();ticket.job.cancel()
    }
}
