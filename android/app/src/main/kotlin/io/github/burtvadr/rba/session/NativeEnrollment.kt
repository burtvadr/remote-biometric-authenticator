package io.github.burtvadr.rba.session

import java.nio.ByteBuffer

/** Single-use Rust SPAKE2 exchange. No native pointers or keys enter Kotlin. */
internal object NativeEnrollment {
    init { System.loadLibrary("rba_enrollment_jni") }
    @JvmStatic external fun generateCode(): ByteArray
    @JvmStatic private external fun startDevice(code: ByteArray, context: ByteArray): ByteArray
    @JvmStatic private external fun finishDevice(handle: Long, share: ByteArray, tag: ByteArray): ByteArray
    @JvmStatic private external fun cancelDevice(handle: Long)

    class Exchange private constructor(private var handle: Long, val share: ByteArray) : AutoCloseable {
        @Synchronized fun confirm(hostShare: ByteArray, hostTag: ByteArray): ByteArray {
            check(handle != 0L) { "enrollment already consumed" }
            val id = handle
            handle = 0L
            return finishDevice(id, hostShare, hostTag)
        }
        @Synchronized override fun close() {
            if (handle != 0L) { cancelDevice(handle); handle = 0L }
        }
        companion object {
            fun start(code: ByteArray, context: ByteArray): Exchange {
                val bytes = try { startDevice(code, context) } finally { code.fill(0) }
                check(bytes.size == 73)
                return Exchange(ByteBuffer.wrap(bytes).long, bytes.copyOfRange(8, 73))
            }
        }
    }
}
