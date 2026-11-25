package io.github.burtvadr.rba.session

import java.nio.ByteBuffer
import io.github.burtvadr.rba.protocol.V2Enrollment

/** Single-use Rust SPAKE2 exchange. No native pointers or keys enter Kotlin. */
internal object NativeEnrollment {
    init { System.loadLibrary("rba_enrollment_jni") }
    @JvmStatic external fun generateCode(): ByteArray
    @JvmStatic private external fun startDevice(code: ByteArray, context: ByteArray): ByteArray
    @JvmStatic private external fun startDeviceV2(code: ByteArray, host: ByteArray, credential: ByteArray, aad: ByteArray): ByteArray
    @JvmStatic private external fun finishDevice(handle: Long, share: ByteArray, tag: ByteArray): ByteArray
    @JvmStatic private external fun cancelDevice(handle: Long)

    val v2Pake = object : V2Enrollment.Pake {
        override fun generateCode(): ByteArray = NativeEnrollment.generateCode()
        override fun start(code: ByteArray, host: ByteArray, credential: ByteArray, aad: ByteArray): V2Enrollment.Exchange =
            Exchange.startV2(code, host, credential, aad)
    }

    class Exchange private constructor(private var handle: Long, override val share: ByteArray) : V2Enrollment.Exchange {
        @Synchronized override fun confirm(hostShare: ByteArray, hostTag: ByteArray): ByteArray {
            check(handle != 0L) { "enrollment already consumed" }
            val id = handle
            handle = 0L
            return finishDevice(id, hostShare, hostTag)
        }
        @Synchronized override fun close() {
            if (handle != 0L) { cancelDevice(handle); handle = 0L }
        }
        companion object {
            fun startV2(code: ByteArray, host: ByteArray, credential: ByteArray, aad: ByteArray): Exchange {
                val bytes = try { startDeviceV2(code, host, credential, aad) } finally { code.fill(0) }
                check(bytes.size == 73)
                return Exchange(ByteBuffer.wrap(bytes).long, bytes.copyOfRange(8, 73))
            }
            fun start(code: ByteArray, context: ByteArray): Exchange {
                val bytes = try { startDevice(code, context) } finally { code.fill(0) }
                check(bytes.size == 73)
                return Exchange(ByteBuffer.wrap(bytes).long, bytes.copyOfRange(8, 73))
            }
        }
    }
}
