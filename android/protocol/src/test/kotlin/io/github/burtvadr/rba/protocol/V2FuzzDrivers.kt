package io.github.burtvadr.rba.protocol

import java.io.ByteArrayInputStream
import java.io.EOFException
import java.io.File

/** Standalone byte-array entry points for Jazzer; no app or native adapter. */
object V2JvmFrameFuzz {
    @JvmStatic fun fuzzerTestOneInput(data:ByteArray) {
        if(data.size>V2Wire.HEADER_LEN+V2Wire.MAX_PAYLOAD)return
        val input=ByteArrayInputStream(data)
        val frame=try{V2Wire.readFrame(input)}catch(_:V2Wire.Invalid){return}catch(_:EOFException){return}
        val used=data.size-input.available()
        val encoded=V2Wire.encodeFrame(frame.first.messageType,frame.second)
        check(encoded.contentEquals(data.copyOf(used)))
        val typed=try{V2Message.Message.read(ByteArrayInputStream(encoded))}catch(_:V2Wire.Invalid){return}
        check(typed.encode().contentEquals(encoded))
    }
}
object V2JvmPayloadFuzz {
    private val kinds=(10..24).toList()+(30..38).toList()
    @JvmStatic fun fuzzerTestOneInput(data:ByteArray){
        if(data.size !in 2..(V2Wire.MAX_PAYLOAD+1))return
        val bytes=data.copyOfRange(1,data.size)
        val value=try{V2Wire.decodePayload(bytes)}catch(_:V2Wire.Invalid){return}
        check(V2Wire.encodePayload(value).contentEquals(bytes))
        val kind=V2Message.Kind.fromCode(kinds[(data[0].toInt() and 255)%kinds.size])
        val msg=try{V2Message.Message.create(kind,value)}catch(_:V2Wire.Invalid){return}
        val encoded=msg.encode()
        check(encoded.copyOfRange(V2Wire.HEADER_LEN,encoded.size).contentEquals(bytes))
        check(V2Message.Message.read(ByteArrayInputStream(encoded)).encode().contentEquals(encoded))
    }
}
object V2JvmStateFuzz {
    @JvmStatic fun fuzzerTestOneInput(data:ByteArray){
        if(data.size>35)return
        run(File(System.getProperty("rba.vectors.dir","protocol/test-vectors")),data)
    }
    fun run(dir:File,data:ByteArray):Int {
        val branch=data.firstOrNull()?.toInt()?:0
        val trace=if(data.isEmpty())byteArrayOf() else data.copyOfRange(1,data.size)
        return if(branch and 1==0)V2AuthenticationTests.run(dir,trace) else V2EnrollmentTests.run(dir,trace)
    }
    fun replay(dir:File):Int {
        var traces=0
        for(stage in 0..3)for(fault in 0..5){run(dir,byteArrayOf(0,stage.toByte(),fault.toByte(),0,1,2,0));traces++}
        for(direction in 0..1)for(fault in 0..8){run(dir,byteArrayOf(1,direction.toByte(),fault.toByte(),0,1,2,0));traces++}
        return traces
    }
}

/** Replay the exact generated parser corpus without instrumentation. */
object V2JvmParserReplay {
    @JvmStatic fun main(args:Array<String>){
        require(args.size==1){"usage: V2JvmParserReplay <corpus-directory>"}
        val root=File(args[0]);var total=0
        for((name,driver) in listOf("v2_frame" to V2JvmFrameFuzz::fuzzerTestOneInput,"v2_payload" to V2JvmPayloadFuzz::fuzzerTestOneInput)){
            val files=File(root,name).listFiles()?.filter{it.isFile}?.sortedBy{it.name}?:error("missing corpus: $name")
            check(files.isNotEmpty());for(f in files){driver(f.readBytes());total++}
            println("PASS: ${files.size} JVM $name corpus inputs")
        }
        println("PASS: $total JVM parser corpus inputs (uninstrumented)")
    }
}
