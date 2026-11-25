package io.github.burtvadr.rba.runtime

import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking

internal object V2NotificationGateChecks {
    fun run():Int=runBlocking {
        var now=100L;var count=0
        fun expect(v:Boolean){check(v);count++}
        val gate=V2NotificationGate<String>{now}
        val firstJob=Job()
        expect(!gate.attach("stale","UI"))
        val first=gate.open("first",200,firstJob)
        expect(runCatching{gate.open("duplicate",200,Job())}.isFailure)
        expect(!gate.attach("wrong","UI"));expect(firstJob.isActive)
        gate.abandon("first");expect(firstJob.isActive) // not yet attached
        expect(gate.attach("first","UI"));expect(first.await()=="UI")
        expect(!gate.attach("first","second UI"))
        gate.abandon("stale");expect(firstJob.isActive)
        gate.abandon("first");expect(!firstJob.isActive)
        expect(!gate.attach("first","UI"))
        val secondJob=Job();val second=gate.open("second",200,secondJob)
        expect(gate.release(first)=="UI");expect(gate.release(first)==null);expect(!gate.attach("first","UI"))
        now=200;expect(!gate.attach("second","UI"))
        gate.release(second);expect(runCatching{second.await()}.isFailure);expect(secondJob.isActive)
        val thirdJob=Job();val third=gate.open("third",300,thirdJob)
        gate.stop();expect(!thirdJob.isActive);expect(runCatching{third.await()}.isFailure)
        expect(!gate.attach("third","UI"))
        expect(runCatching{gate.open("past",now,Job())}.isFailure)
        expect(runCatching{gate.open("far",now+60001,Job())}.isFailure)
        val dead=Job();dead.cancel();expect(runCatching{gate.open("dead",300,dead)}.isFailure)
        val finalJob=Job();val final=gate.open("final",300,finalJob);finalJob.cancel()
        expect(!gate.attach("final","UI"));gate.release(final)
        count
    }
}
