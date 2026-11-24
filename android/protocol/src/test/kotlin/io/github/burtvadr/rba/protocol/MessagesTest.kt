package io.github.burtvadr.rba.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Value semantics for the opaque protocol identifiers.
 *
 * These are easy to get wrong: Kotlin's generated equality for an inline class
 * wrapping `ByteArray` compares the array by reference, which would make two ids
 * with identical bytes unequal. Every "is this the same host/device/request?"
 * check in the app depends on content equality.
 */
class MessagesTest {

    @Test
    fun `ids with identical bytes are equal`() {
        val a = Id.fromHex("00112233445566778899aabbccddeeff")
        val b = Id(Hex.decode("00112233445566778899aabbccddeeff"))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `ids with different bytes are not equal`() {
        val a = Id.fromHex("00112233445566778899aabbccddeeff")
        val b = Id.fromHex("00112233445566778899aabbccddee00")
        assertNotEquals(a, b)
    }

    @Test
    fun `ids can be used as map keys`() {
        val id = Id.fromHex("00112233445566778899aabbccddeeff")
        val map = mapOf(id to "paired")
        assertEquals("paired", map[Id.fromHex("00112233445566778899aabbccddeeff")])
    }

    @Test
    fun `challenges with identical bytes are equal`() {
        val bytes = ByteArray(Limits.CHALLENGE_LEN) { it.toByte() }
        assertEquals(Challenge(bytes.copyOf()), Challenge(bytes.copyOf()))
    }

    @Test
    fun `legacy pairing payload is rejected`() {
        val old = Cbor.encode(Cbor.ofMap("code" to Cbor.text("123456")))
        assertTrue(runCatching { PairingStart.fromPayload(old) }.isFailure)
    }

    @Test
    fun `an identifier rejects the wrong length`() {
        val threw = runCatching { Id(ByteArray(Limits.ID_LEN - 1)) }.isFailure
        assertTrue(threw, "a short identifier must be rejected")
    }
}
