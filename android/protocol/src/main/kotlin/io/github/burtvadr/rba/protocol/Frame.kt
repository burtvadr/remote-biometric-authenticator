package io.github.burtvadr.rba.protocol

/**
 * Protocol framing (`PROTOCOL.md` §4).
 *
 * Strict alignment, no resynchronisation: a receiver consumes exactly
 * `13 + payload_len` bytes. Scanning the stream for the magic value would let an
 * attacker choose where frames begin, because `PAF1` can legitimately occur
 * inside a payload. A stream that loses alignment is failed closed.
 */
class Frame(
    val version: Int = PROTOCOL_VERSION,
    val msgType: Int,
    val flags: Int = 0,
    val payload: ByteArray,
) {
    /** Structural equality, so frames can be compared directly in tests. */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Frame) return false
        return version == other.version &&
            msgType == other.msgType &&
            flags == other.flags &&
            payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + msgType
        result = 31 * result + flags
        result = 31 * result + payload.contentHashCode()
        return result
    }

    override fun toString(): String =
        "Frame(v=$version, type=$msgType, flags=$flags, payload=${payload.size}B)"

    fun encode(): ByteArray {
        val out = ByteArray(HEADER_LEN + payload.size)
        MAGIC.copyInto(out, 0)
        out[4] = version.toByte()
        out[5] = ((msgType shr 8) and 0xFF).toByte()
        out[6] = (msgType and 0xFF).toByte()
        out[7] = ((flags shr 8) and 0xFF).toByte()
        out[8] = (flags and 0xFF).toByte()
        out[9] = ((payload.size shr 24) and 0xFF).toByte()
        out[10] = ((payload.size shr 16) and 0xFF).toByte()
        out[11] = ((payload.size shr 8) and 0xFF).toByte()
        out[12] = (payload.size and 0xFF).toByte()
        payload.copyInto(out, HEADER_LEN)
        return out
    }

    class FrameException(message: String) : IllegalArgumentException(message)

    companion object {
        val MAGIC = byteArrayOf('P'.code.toByte(), 'A'.code.toByte(), 'F'.code.toByte(), '1'.code.toByte())
        const val HEADER_LEN = 13
        const val PROTOCOL_VERSION = 1
        const val MAX_FRAME_PAYLOAD = 65_536

        /**
         * Decodes the frame at the start of [buffer].
         *
         * Returns the frame and the number of bytes consumed, or `null` when more
         * bytes are needed (as opposed to the input being malformed).
         */
        fun decode(buffer: ByteArray, offset: Int = 0, limit: Int = buffer.size): Pair<Frame, Int>? {
            if (limit - offset < HEADER_LEN) return null
            for (i in 0 until 4) {
                if (buffer[offset + i] != MAGIC[i]) {
                    throw FrameException("bad frame magic")
                }
            }
            val version = buffer[offset + 4].toInt() and 0xFF
            if (version != PROTOCOL_VERSION) {
                throw FrameException("unsupported protocol version $version")
            }
            val msgType = ((buffer[offset + 5].toInt() and 0xFF) shl 8) or
                (buffer[offset + 6].toInt() and 0xFF)
            val flags = ((buffer[offset + 7].toInt() and 0xFF) shl 8) or
                (buffer[offset + 8].toInt() and 0xFF)
            if (flags != 0) throw FrameException("nonzero frame flags $flags")
            var len = 0L
            for (i in 9..12) {
                len = (len shl 8) or (buffer[offset + i].toLong() and 0xFF)
            }
            if (len > MAX_FRAME_PAYLOAD) {
                throw FrameException("frame payload length $len exceeds the limit")
            }
            val total = HEADER_LEN + len.toInt()
            if (limit - offset < total) return null
            val payload = buffer.copyOfRange(offset + HEADER_LEN, offset + total)
            return Frame(version, msgType, flags, payload) to total
        }
    }
}