package io.github.burtvadr.rba.transport

import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Message
import kotlinx.coroutines.*
import java.io.EOFException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Uninstrumented JVM tests of the actual operation coordinator, with a
 * blocking, close-aware test link. Not a TLS or Android hardware test. */
internal object V2OperationWireChecks {
    private fun now()=System.nanoTime()/1_000_000
    private fun msg(k:V2Message.Kind)=V2Message.Message.create(k,Cbor.ofMap("session_id" to Cbor.bytes(ByteArray(16){1}),"request_id" to Cbor.bytes(ByteArray(16){2})))
    private class Link:V2OperationWire.Link {
        val reads=AtomicInteger();val active=AtomicInteger();val peak=AtomicInteger();val writes=AtomicInteger();val closed=AtomicInteger()
        val started=CompletableDeferred<Unit>()
        private val inbound=LinkedBlockingQueue<Any>()
        fun peer(m:V2Message.Message){inbound.add(m)}
        fun eof(){inbound.add(EOFException("peer closed"))}
        override fun read(deadline:Long):V2Message.Message {
            reads.incrementAndGet();val n=active.incrementAndGet();peak.updateAndGet{maxOf(it,n)};started.complete(Unit)
            try{val next=inbound.poll((deadline-now()).coerceAtLeast(1),TimeUnit.MILLISECONDS)?:throw EOFException("deadline")
                if(next is Exception)throw next
                return next as V2Message.Message
            }finally{active.decrementAndGet()}
        }
        override fun write(message:V2Message.Message,deadline:Long){check(closed.get()==0);writes.incrementAndGet()}
        override fun close(){if(closed.incrementAndGet()==1)eof()}
    }
    fun run():Int=runBlocking {
        var count=0
        fun ck(ok:Boolean){check(ok){"operation wire check ${count+1}"};count++}
        suspend fun scenario(link:Link,block:suspend (V2OperationWire)->Unit)=supervisorScope {
            V2OperationWire(this,link,::now).use{block(it)}
        }
        // Two UI steps reuse the same pending read; next receive consumes it.
        Link().also{l->scenario(l){w->val d=now()+5000
            ck(w.interaction(d){l.started.await();"first"}=="first")
            ck(w.interaction(d){"second"}=="second")
            ck(l.reads.get()==1);w.send(msg(V2Message.Kind.CANCEL),d);l.peer(msg(V2Message.Kind.CANCEL))
            ck(w.receive(V2Message.Kind.CANCEL,d).kind==V2Message.Kind.CANCEL);ck(l.writes.get()==1)
        };ck(l.peak.get()==1);ck(l.closed.get()==1)}
        // Peer sends unexpected data while user is waiting: cancel the UI.
        Link().also{l->var dismissed=false;scenario(l){w->val d=now()+5000
            val r=runCatching{w.interaction(d){try{l.started.await();l.peer(msg(V2Message.Kind.CANCEL));awaitCancellation()}finally{dismissed=true}}}
            ck(r.isFailure);ck(dismissed);ck(l.writes.get()==0)
            ck(runCatching{w.send(msg(V2Message.Kind.CANCEL),d)}.isFailure)
        };ck(l.closed.get()==1)}
        // EOF during a local prompt terminates the operation and dismisses UI.
        Link().also{l->var dismissed=false;scenario(l){w->val d=now()+5000
            ck(runCatching{w.interaction(d){try{l.started.await();l.eof();awaitCancellation()}finally{dismissed=true}}}.isFailure)
            ck(dismissed);ck(l.writes.get()==0)
        };ck(l.closed.get()==1)}
        // Explicit local cancellation closes carrier before joining the read.
        Link().also{l->var dismissed=false;val uiStarted=CompletableDeferred<Unit>();supervisorScope{
            val job=launch {scenario(l){w->w.interaction(now()+5000){try{uiStarted.complete(Unit);awaitCancellation()}finally{dismissed=true}}}}
            uiStarted.await();job.cancelAndJoin();ck(job.isCancelled)
        };ck(dismissed);ck(l.closed.get()==1);ck(l.active.get()==0)}
        // Expired operation rejects I/O without starting a new read.
        Link().also{l->scenario(l){w->ck(runCatching{w.receive(V2Message.Kind.CANCEL,now()-1)}.isFailure);ck(l.reads.get()==0)}}
        // Wrong message kind cannot be consumed as the expected response.
        Link().also{l->scenario(l){w->l.peer(msg(V2Message.Kind.CANCEL));ck(runCatching{w.receive(V2Message.Kind.AUTHRESULT,now()+5000)}.isFailure)}}
        println("PASS: $count V2 operation wire checks")
        count
    }
}
