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
    fun `pairing code uses more than one byte`() {
        // The old implementation used p[0] % 1_000_000, which can only produce
        // 000000..000255. At least one deterministic session must escape it.
        val hostEph = encodeEcpPublicKey(
            generateP256KeyPair().public as java.security.interfaces.ECPublicKey,
        )
        for (i in 0 until 64) {
            val session = PairingSession(
                Id(ByteArray(Limits.ID_LEN) { i.toByte() }),
                ByteArray(Limits.CHALLENGE_LEN) { i.toByte() },
                hostEph,
            )
            session.derive(
                hostId = Id(ByteArray(Limits.ID_LEN) { (i + 2).toByte() }),
                deviceId = Id(ByteArray(Limits.ID_LEN) { (i + 3).toByte() }),
                hostPub = ByteArray(Limits.PUBKEY_LEN) { (i + 4).toByte() },
                devicePub = ByteArray(Limits.PUBKEY_LEN) { (i + 5).toByte() },
                deviceNonce = ByteArray(Limits.CHALLENGE_LEN) { (i + 1).toByte() },
            )
            if (session.code().toInt() > 255) return
        }
        error("all pairing codes were <= 255; the code is still truncated to one byte")
    }

    @Test
    fun `an identifier rejects the wrong length`() {
        val threw = runCatching { Id(ByteArray(Limits.ID_LEN - 1)) }.isFailure
        assertTrue(threw, "a short identifier must be rejected")
    }
}
