package io.github.burtvadr.rba.transport

import io.github.burtvadr.rba.protocol.V2Message
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select

/** One serialized operation owns one channel. The single outstanding read
 * monitors EOF and unexpected peer messages during local interaction. A read
 * is never abandoned and restarted on the same byte stream. */
internal class V2OperationWire(
    private val scope:CoroutineScope,
    private val channel:Link,
    private val mono:()->Long,
):AutoCloseable {
    interface Link:AutoCloseable {
        fun read(deadline:Long):V2Message.Message
        fun write(message:V2Message.Message,deadline:Long)
    }
    private var pending:Deferred<Result<V2Message.Message>>?=null
    private var terminal=false
    private fun live(deadline:Long):Long {
        check(!terminal)
        val remaining=deadline-mono();check(remaining in 1..120000)
        return remaining
    }
    private fun readAhead(deadline:Long):Deferred<Result<V2Message.Message>> {
        live(deadline)
        return pending?:scope.async(Dispatchers.IO){try{Result.success(channel.read(deadline))}catch(e:Exception){Result.failure(e)}}.also{pending=it}
    }
    private inline fun <T> guard(work:()->T):T=try{work()}catch(e:Exception){
        try{close()}catch(cleanup:Exception){e.addSuppressed(cleanup)};throw e
    }
    suspend fun receive(kind:V2Message.Kind,deadline:Long):V2Message.Message=guard {
        val read=readAhead(deadline)
        val message=withTimeout(live(deadline)){read.await().getOrThrow()}
        pending=null
        live(deadline);check(message.kind==kind)
        message
    }
    /** Watch the remote connection during UI waits. The pending read is kept
     * for the next expected response, so only one reader exists at any time.
     * Unexpected data or EOF cancels the UI; a late callback cannot continue. */
    suspend fun <T> interaction(deadline:Long,work:suspend ()->T):T=guard {coroutineScope {
        val read=readAhead(deadline)
        check(!read.isCompleted)
        val ui=async(start=CoroutineStart.LAZY){work()}
        try {
            val result=withTimeout(live(deadline)){
                select<T>{
                    read.onAwait { it.getOrThrow();error("Unexpected peer message during local interaction") }
                    ui.onAwait { it }
                }
            }
            live(deadline);check(!read.isCompleted)
            result
        } finally { ui.cancel() }
    }}
    suspend fun send(message:V2Message.Message,deadline:Long):Unit=guard {
        live(deadline);check(pending?.isCompleted!=true)
        withContext(Dispatchers.IO){channel.write(message,deadline)}
        live(deadline);Unit
    }
    override fun close(){
        if(terminal)return
        terminal=true
        // Close the carrier before cancelling the blocking read. Cancelling
        // a coroutine alone cannot interrupt a blocking TLS socket read.
        try{channel.close()}finally{pending?.cancel();pending=null}
    }
}
