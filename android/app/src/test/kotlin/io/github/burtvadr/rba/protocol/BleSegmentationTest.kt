package io.github.burtvadr.rba.protocol

import io.github.burtvadr.rba.transport.BleFraming
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the BLE segmentation adapter.
 *
 * These run on the JVM with no device, because the framing arithmetic has no
 * Android dependency. That arithmetic is what makes the two transports carry
 * identical bytes, so it is worth testing directly.
 */
class BleSegmentationTest {

    private fun frame(payload: Int): Frame =
        Frame(msgType = 12, payload = ByteArray(payload) { (it % 251).toByte() })

    @Test
    fun `segmentation respects the GATT MTU`() {
        val segments = BleFraming.segment(frame(1000))
        assertTrue("every segment must fit in 20 bytes", segments.all { it.size <= BleFraming.SEGMENT_SIZE })
        // 13 header + 1000 payload = 1013 bytes, so 51 segments of at most 20.
        assertEquals(51, segments.size)
    }

    @Test
    fun `reassembly completes only once every segment has arrived`() {
        val original = frame(200)
        val segments = BleFraming.segment(original)
        val link = BleFraming.Link()

        // Every segment but the last yields nothing.
        for (i in 0 until segments.size - 1) {
            assertNull("frame completed early at segment $i", link.push(segments[i]).getOrNull())
        }
        val completed = link.push(segments.last()).getOrNull()
        assertNotNull("the last segment must complete the frame", completed)
        assertEquals(original.payload.toList(), completed!!.payload.toList())
        assertEquals(original.msgType, completed.msgType)
    }

    @Test
    fun `a frame that fits in one segment completes immediately`() {
        val original = Frame(msgType = 20, payload = ByteArray(0))
        val segments = BleFraming.segment(original)
        assertEquals(1, segments.size)
        assertEquals(original, BleFraming.reassemble(segments))
    }

    @Test
    fun `consecutive frames do not bleed into each other`() {
        val first = Frame(msgType = 12, payload = ByteArray(30))
        val second = Frame(msgType = 13, payload = ByteArray(300))
        val link = BleFraming.Link()

        val received = mutableListOf<Frame>()
        (BleFraming.segment(first) + BleFraming.segment(second)).forEach {
            link.push(it).getOrNull()?.let(received::add)
        }
        assertEquals(2, received.size)
        assertEquals(first.payload.toList(), received[0].payload.toList())
        assertEquals(second.payload.toList(), received[1].payload.toList())
        assertEquals(12, received[0].msgType)
        assertEquals(13, received[1].msgType)
    }

    @Test
    fun `a declared length beyond the frame cap is rejected immediately`() {
        val link = BleFraming.Link()
        val segments = BleFraming.segment(frame(10)).toMutableList()
        // Declare a payload larger than the protocol's hard cap. This cannot be a
        // slow link, so it must be refused on the first segment.
        segments[0] = segments[0].copyOf().also {
            it[9] = 0x00
            it[10] = 0x20
            it[11] = 0x00
            it[12] = 0x00 // 0x00200000 = 2 MiB, far beyond 64 KiB
        }
        val result = link.push(segments[0])
        assertTrue("an over-cap declared length must be rejected", result.isFailure)
        assertTrue("the link must be poisoned after a malformed frame", link.isPoisoned())
        assertTrue("a poisoned link must refuse input", link.push(byteArrayOf(1, 2, 3)).isFailure)
    }

    @Test
    fun `a merely long declared length is treated as incomplete, not as an error`() {
        // BLE cannot distinguish "more segments are coming" from "the length is a
        // lie", so a length within the cap is treated as incomplete. This is a
        // liveness property: the peer is expected to be trusted enough not to stall
        // forever, and the authentication timeout bounds the damage.
        val link = BleFraming.Link()
        val segments = BleFraming.segment(frame(10)).toMutableList()
        segments[0] = segments[0].copyOf().also { it[12] = 0x40 } // claim 64 bytes
        for (s in segments) {
            assertTrue(link.push(s).isSuccess)
        }
        assertTrue("no frame completes, so the link is not poisoned", !link.isPoisoned())
    }

    @Test
    fun `a reset link accepts well formed frames again`() {
        val link = BleFraming.Link()
        val segments = BleFraming.segment(frame(10)).toMutableList()
        segments[0] = segments[0].copyOf().also {
            it[9] = 0x00
            it[10] = 0x20
            it[11] = 0x00
            it[12] = 0x00
        }
        for (s in segments) {
            link.push(s)
        }
        assertTrue(link.isPoisoned())

        link.reset()
        assertTrue(!link.isPoisoned())

        val good = frame(20)
        var got: Frame? = null
        for (s in BleFraming.segment(good)) {
            link.push(s).getOrNull()?.let { got = it }
        }
        assertNotNull("a reset link must work again", got)
        assertEquals(good.payload.toList(), got!!.payload.toList())
    }

    @Test
    fun `an oversized segment is refused`() {
        val link = BleFraming.Link()
        assertTrue(
            link.push(ByteArray(BleFraming.SEGMENT_SIZE + 1)).isFailure,
        )
    }

    @Test
    fun `the project UUIDs are the documented ones`() {
        assertEquals("8f1c0001-9d2b-4a7e-b0c4-5f6a71c3d801", BleFraming.SERVICE_UUID.toString())
        assertEquals("8f1c0002-9d2b-4a7e-b0c4-5f6a71c3d801", BleFraming.RX_CHARACTERISTIC_UUID.toString())
        assertEquals("8f1c0003-9d2b-4a7e-b0c4-5f6a71c3d801", BleFraming.TX_CHARACTERISTIC_UUID.toString())
        assertEquals(20, BleFraming.SEGMENT_SIZE)
    }
}
