package io.github.burtvadr.rba.transport

import io.github.burtvadr.rba.protocol.Frame
import java.io.IOException
import java.util.UUID

/**
 * Frame segmentation for the BLE transport.
 *
 * Deliberately free of any Android dependency: BLE carries at most 20 bytes per
 * characteristic value, so frames must be split and reassembled. That arithmetic
 * is the part that has to be correct for the two transports to be
 * security-identical, so it lives here where it can be tested on the JVM without
 * a device.
 *
 * Frame bytes are copied verbatim. The adapter never rewrites them, which is what
 * keeps the protocol byte-identical to the Wi-Fi transport.
 */
object BleFraming {

    /** Project-assigned 128-bit UUIDs (`PROTOCOL.md` §13.2). */
    val SERVICE_UUID: UUID = UUID.fromString("8f1c0001-9d2b-4a7e-b0c4-5f6a71c3d801")
    val RX_CHARACTERISTIC_UUID: UUID = UUID.fromString("8f1c0002-9d2b-4a7e-b0c4-5f6a71c3d801")
    val TX_CHARACTERISTIC_UUID: UUID = UUID.fromString("8f1c0003-9d2b-4a7e-b0c4-5f6a71c3d801")

    /** The project's own read/write characteristic descriptor. */
    val CLIENT_CHARACTERISTIC_CONFIG: UUID =
        UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    /** A single characteristic value carries at most MTU-3 = 20 bytes. */
    const val SEGMENT_SIZE = 20

    /** Splits an encoded frame into GATT-sized segments. */
    fun segment(frame: Frame): List<ByteArray> {
        val bytes = frame.encode()
        if (bytes.isEmpty()) return listOf(ByteArray(0))
        return bytes.asList().chunked(SEGMENT_SIZE).map { it.toByteArray() }
    }

    /**
     * Reassembles segments into a frame.
     *
     * Returns `null` while the frame is still incomplete. A declared length that
     * cannot be right, or a payload that does not decode, is an error: on BLE
     * there is no resynchronisation point, so a malformed link is dropped rather
     * than guessed at.
     */
    fun reassemble(segments: List<ByteArray>): Frame? {
        if (segments.isEmpty()) return null
        if (segments[0].size < Frame.HEADER_LEN) return null
        val header = segments[0]
        val payloadLength = ((header[9].toInt() and 0xFF) shl 24) or
            ((header[10].toInt() and 0xFF) shl 16) or
            ((header[11].toInt() and 0xFF) shl 8) or
            (header[12].toInt() and 0xFF)
        if (payloadLength > Frame.MAX_FRAME_PAYLOAD) {
            throw IOException("declared payload $payloadLength exceeds the limit")
        }
        val total = Frame.HEADER_LEN + payloadLength
        val have = segments.sumOf { it.size }
        if (have < total) return null
        if (have > total) throw IOException("received $have bytes for a $total-byte frame")

        val buf = ByteArray(total)
        var offset = 0
        for (segment in segments) {
            segment.copyInto(buf, offset)
            offset += segment.size
        }
        val (frame, consumed) = Frame.decode(buf) ?: throw IOException("frame did not decode")
        if (consumed != total) throw IOException("frame consumed $consumed of $total bytes")
        return frame
    }

    /** Tracks the partially received frame for one link. */
    class Link {
        private val segments = mutableListOf<ByteArray>()

        @Volatile
        private var poisoned = false

        /** Feeds one characteristic value and returns any frame that completed. */
        fun push(segment: ByteArray): Result<Frame?> {
            if (poisoned) return Result.failure(IOException("link poisoned after a malformed frame"))
            if (segment.size > SEGMENT_SIZE) {
                return Result.failure(IOException("segment larger than the GATT MTU allows"))
            }
            segments.add(segment.copyOf())
            val frame = try {
                reassemble(segments.toList())
            } catch (e: IOException) {
                // Drop the buffer so a reconnect can start clean, but keep the link
                // poisoned so it is not re-synchronised mid-frame.
                segments.clear()
                poisoned = true
                return Result.failure(e)
            }
            if (frame != null) {
                // A completed frame consumes the whole buffer. Leaving the segments
                // in place would let the next frame's bytes be appended to this one
                // and the two would decode into a single garbage frame.
                segments.clear()
            }
            return Result.success(frame)
        }

        /** Abandons any partial frame and un-poisons the link, e.g. after reconnect. */
        fun reset() {
            segments.clear()
            poisoned = false
        }

        fun pendingSegments(): Int = segments.size

        fun isPoisoned(): Boolean = poisoned
    }
}