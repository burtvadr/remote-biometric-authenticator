package io.github.burtvadr.rba.session

import io.github.burtvadr.rba.protocol.Id
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A device pairs with more than one PC -- a laptop, a desktop, a VM -- so these guard
 * that a second host is neither lost nor allowed to displace the first.
 *
 * The failure these exist to prevent: the paired hosts are held in a list in memory, the
 * system restarts the app at some point, and a host silently disappears. A vanished
 * host is indistinguishable from a revoked one, so it arrives as "the app sometimes
 * stops working" rather than as a bug report.
 *
 * All pure JVM, no Android: [HostRegistry] and [HostCodec] hold the rules, and
 * [HostStore] is only load-and-save plumbing on top of them.
 */
class HostStoreTest {

    private fun host(seed: Int, name: String = "host-$seed") = KnownHost(
        hostId = Id.random(),
        keyId = "key-%08x".format(seed),
        // A 65-byte uncompressed P-256 point. The codec must reject any other length,
        // or a corrupt record would persist and only fail much later during pairing.
        publicKeyBytes = ByteArray(65) { (seed + it).toByte() },
        pinnedCertificate = null,
        hostName = name,
    )

    @Test
    fun `starts empty`() {
        val registry = HostRegistry()
        assertEquals(emptyList<KnownHost>(), registry.all())
        assertEquals(0, registry.size)
        assertFalse(registry.isPaired(Id.random()))
    }

    @Test
    fun `three hosts coexist and none displaces another`() {
        val registry = HostRegistry()
            .put(host(1, "laptop"))
            .put(host(2, "desktop"))
            .put(host(3, "build-box"))

        assertEquals(3, registry.size)
        assertEquals(
            setOf("laptop", "desktop", "build-box"),
            registry.all().map { it.hostName }.toSet(),
        )
    }

    @Test
    fun `re-pairing a host replaces only that host`() {
        val laptop = host(1, "laptop")
        val desktop = host(2, "desktop")
        val registry = HostRegistry().put(laptop).put(desktop)

        // Same host id, rotated key: an ordinary re-pair, not a new machine.
        val rotated = laptop.copy(keyId = "rotated", hostName = "laptop (rotated)")
        registry.put(rotated)

        assertEquals(2, registry.size)
        assertEquals("rotated", registry.get(laptop.hostId)?.keyId)
        assertEquals("desktop", registry.get(desktop.hostId)?.hostName)
    }

    @Test
    fun `removing one host leaves the others`() {
        val laptop = host(1, "laptop")
        val desktop = host(2, "desktop")
        val registry = HostRegistry().put(laptop).put(desktop)

        assertTrue(registry.remove(laptop.hostId))
        assertEquals(listOf("desktop"), registry.all().map { it.hostName })
    }

    @Test
    fun `removing a host that was never paired reports it`() {
        assertFalse(HostRegistry().remove(Id.random()))
    }

    @Test
    fun `records survive a round-trip through the store encoding`() {
        val original = listOf(
            host(1, "laptop"),
            host(2, "desktop"),
            host(3, "a host with spaces and a (very) long name"),
        )

        val restored = HostCodec.decodeAll(HostCodec.encodeAll(original))

        assertEquals(3, restored.size)
        for (before in original) {
            val after = restored.first { it.hostId.toHex() == before.hostId.toHex() }
            assertEquals(before.keyId, after.keyId)
            assertEquals(before.hostName, after.hostName)
            assertEquals(before.publicKeyBytes.toList(), after.publicKeyBytes.toList())
            assertNull(after.pinnedCertificate)
        }
    }

    @Test
    fun `a later record for the same id wins, as a re-pairing would`() {
        // De-duplication is the registry's job, not the codec's: the codec is a plain
        // serializer and must not silently drop records. This is the path a reload
        // actually takes, since a blob can only end up with two records of one id if a
        // re-pairing was appended without rewriting the earlier one.
        val first = host(1, "laptop")
        val again = first.copy(hostName = "laptop (re-paired)")

        val restored = HostRegistry(
            HostCodec.decodeAll(HostCodec.encodeAll(listOf(first, again)))
        )

        assertEquals(1, restored.size)
        assertEquals("laptop (re-paired)", restored.all()[0].hostName)
    }

    @Test
    fun `a host name with separators and newlines cannot forge a field`() {
        // The decoder splits records on newlines and fields on a unit separator. A name
        // carrying either would otherwise let operator-typed text invent a host record.
        val hostile = host(9, "evil-PC\u001Fhosts_v1\nQUJD")

        val restored = HostCodec.decodeAll(HostCodec.encodeAll(listOf(hostile)))

        assertEquals(1, restored.size)
        assertEquals(hostile.hostName, restored[0].hostName)
        assertEquals(hostile.keyId, restored[0].keyId)
    }

    @Test
    fun `revocation token survives the codec`() {
        val original = host(7).copy(revocationToken = ByteArray(32) { it.toByte() })
        val restored = HostCodec.decodeAll(HostCodec.encodeAll(listOf(original))).single()
        assertTrue(
            "the revocation token must survive a store round-trip",
            original.revocationToken!!.contentEquals(restored.revocationToken),
        )
    }

    @Test
    fun `a corrupt record is rejected rather than half-parsed`() {
        // Better to load nothing and let the user re-pair than to load a record whose
        // fields were guessed at.
        val cases = listOf(
            "this is not a host record at all",
            // five fields, but a 3-byte "public key"
            "${Id.random().toHex()}\u001Fkey\u001FAQID\u001F-\u001FbGFiZWw",
            // too few fields
            "${Id.random().toHex()}\u001Fkey\u001FAQID",
        )
        for (case in cases) {
            val outcome = runCatching { HostCodec.decodeAll(case) }
            assertTrue("must reject: $case", outcome.isFailure)
        }
    }

    @Test
    fun `empty input decodes to nothing`() {
        assertEquals(emptyList<KnownHost>(), HostCodec.decodeAll(""))
        assertEquals(emptyList<KnownHost>(), HostCodec.decodeAll("\n\n  \n"))
    }

    @Test
    fun `equality compares key material by content`() {
        // ByteArray equality is reference equality, so two records decoded from disk
        // would never equal the one just paired. Every caller here compares by id, but
        // leaving a broken equals on a record type is a trap for the next caller.
        val a = host(1, "laptop")
        val b = a.copy()
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(hostName = "desktop"))
    }

    @Test
    fun `distinct hosts get distinct ids`() {
        // The multi-host rules rest on ids being random rather than derived, so two PCs
        // cannot collide on one.
        val ids = (1..64).map { host(it).hostId.toHex() }.toSet()
        assertEquals(64, ids.size)
    }

    @Test
    fun `a registry reloaded from encoded form keeps every host`() {
        // The whole point of persisting: after a restart, all three hosts are still
        // known and can still authenticate.
        val before = HostRegistry().put(host(1, "laptop")).put(host(2, "desktop")).put(host(3, "vm"))
        val after = HostRegistry(HostCodec.decodeAll(HostCodec.encodeAll(before.all())))

        assertEquals(3, after.size)
        for (h in before.all()) {
            assertTrue("still paired after reload: ${h.hostName}", after.isPaired(h.hostId))
        }
    }
}