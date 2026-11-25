package io.github.burtvadr.rba.session

import android.content.ContextWrapper
import io.github.burtvadr.rba.keystore.V2HardwareKeys
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.burtvadr.rba.protocol.Cbor
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.protocol.V2Wire
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Physical-device storage/alias acceptance, not remote attestation or a
 * successful biometric prompt. Requires enrolled strong biometric hardware.
 * Test aliases are fresh, isolated from all real records, and deleted afterward.
 */
@RunWith(AndroidJUnit4::class)
class V2DeviceStoreTest {
    private fun raw(key:ECPublicKey):ByteArray {
        fun coord(n:BigInteger):ByteArray{val v=n.toByteArray();val out=ByteArray(32);val start=maxOf(0,v.size-32);v.copyInto(out,32-(v.size-start),start);return out}
        return byteArrayOf(4)+coord(key.w.affineX)+coord(key.w.affineY)
    }
    @Test fun pendingSurvivesReopenAndOnlyExactRecordActivates(){
        val base=InstrumentationRegistry.getInstrumentation().targetContext
        val isolated=File(base.cacheDir,"v2-store-test-${java.util.UUID.randomUUID()}").apply{check(mkdir())}
        val context=object:ContextWrapper(base){override fun getNoBackupFilesDir()=isolated}
        val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        var keys:V2HardwareKeys.Credential?=null
        try {
            val generated=V2DeviceStore.initialize(context).use { it.generateEnrollmentKeys(context,V2Enrollment.Challenges(ByteArray(32){11},ByteArray(32){12})) }
            keys=generated
            val credential=generated.id();val tk=generated.transportPoint();val bk=generated.biometricPoint()
            val host=raw(KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair().public as ECPublicKey)
            val now=System.currentTimeMillis()/1000
            fun record(receipt:ByteArray)=V2Wire.encodePayload(Cbor.ofMap(
                "host_id" to Cbor.bytes(ByteArray(16){1}),"host_key" to Cbor.bytes(host),"host_cert" to Cbor.bytes(ByteArray(32){2}),
                "transport_key" to Cbor.bytes(tk),"biometric_key" to Cbor.bytes(bk),"created_at" to Cbor.uint(now),"recover_until" to Cbor.uint(now+86400),
                "offer" to Cbor.ofMap("enrollment_id" to Cbor.bytes(ByteArray(16){3}),"credential_id" to Cbor.bytes(credential),"grants" to Cbor.array(emptyList()),"revision" to Cbor.uint(1),"token" to Cbor.bytes(ByteArray(32){4}),"receipt" to Cbor.bytes(receipt))))
            val saved=record(ByteArray(32){5});V2Enrollment.Pending.decode(saved)
            V2DeviceStore.open(context).use{s->s.stage(saved);assertNull(s.active(credential));assertArrayEquals(saved,s.pending(credential)!!.encode());assertTrue(runCatching{s.stage(saved)}.isFailure);assertTrue(runCatching{s.discardUnrecorded(generated)}.isFailure)}
            V2DeviceStore.open(context).use{s->
                assertNull(s.active(credential));assertArrayEquals(saved,s.pending(credential)!!.encode())
                assertTrue(runCatching{s.activate(record(ByteArray(32){6}))}.isFailure);assertNull(s.active(credential))
                s.activate(saved);assertNull(s.pending(credential));assertArrayEquals(saved,s.active(credential)!!.encode());assertTrue(runCatching{s.activate(saved)}.isFailure)
                assertTrue(runCatching{s.discardPending(credential,saved)}.isFailure)
                assertTrue(runCatching{s.discardUnrecorded(generated)}.isFailure)
            }
            V2DeviceStore.open(context).use{s->assertArrayEquals(saved,s.active(credential)!!.encode())}
            assertTrue(runCatching{V2DeviceStore.initialize(context)}.isFailure)
            V2DeviceStore.open(context).use{s->s.beginRevocation(credential);assertNull(s.active(credential));assertFalse(s.revocationAcknowledged(credential));assertArrayEquals(saved,s.revoking(credential).encode())}
            // Revocation retry must not depend on a working biometric key.
            ks.deleteEntry(V2DeviceStore.biometricAlias(credential))
            assertNotNull(V2HardwareKeys.revocationKeyManager(credential,tk))
            V2DeviceStore.open(context).use{s->
                s.beginRevocation(credential);assertNull(s.active(credential));assertTrue(runCatching{s.policySnapshot(credential)}.isFailure)
                assertTrue(runCatching{s.acknowledgeRevocation(credential,record(ByteArray(32){6}))}.isFailure)
                // Isolated storage test simulates the verified receipt boundary.
                s.acknowledgeRevocation(credential,saved);assertTrue(s.revocationAcknowledged(credential));assertTrue(runCatching{s.revoking(credential)}.isFailure)
            }
            V2DeviceStore.open(context).use{s->assertTrue(s.revocationAcknowledged(credential));assertNull(s.active(credential));s.finishRevocationCleanup(credential);assertNull(s.active(credential));assertFalse(ks.containsAlias(V2DeviceStore.transportAlias(credential)));assertFalse(ks.containsAlias(V2DeviceStore.biometricAlias(credential)))}
        }finally{
            // The isolated database is never a real trust store. Remove it
            // before deleting the corresponding test-only aliases.
            isolated.deleteRecursively()
            keys?.let{ks.deleteEntry(V2DeviceStore.transportAlias(it.id()));ks.deleteEntry(V2DeviceStore.biometricAlias(it.id()))}
        }
    }
}
