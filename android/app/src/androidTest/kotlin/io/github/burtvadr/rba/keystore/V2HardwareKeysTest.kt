package io.github.burtvadr.rba.keystore

import android.security.keystore.UserNotAuthenticatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.session.V2DeviceStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.io.ByteArrayInputStream

/** Must run on physical hardware with enrolled strong biometrics. No mock
 * provider and no silent skip. Host trust acceptance is a separate test. */
@RunWith(AndroidJUnit4::class)
class V2HardwareKeysTest {
    @Test fun freshAttestedKeysHaveSeparateRolesAndRequireFreshBiometric() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val rng=SecureRandom()
        val tc=ByteArray(32).apply{rng.nextBytes(this)};val bc=ByteArray(32).apply{rng.nextBytes(this)}
        val keys=V2HardwareKeys.generate(context,V2Enrollment.Challenges(tc,bc))
        try {
            assertFalse(keys.transportPoint().contentEquals(keys.biometricPoint()))
            fun leaf(chain:List<ByteArray>)=CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(chain.first())) as X509Certificate
            assertArrayEquals(tc,V2KeyEncoding.attestationChallenge(leaf(keys.transportChain()).getExtensionValue("1.3.6.1.4.1.11129.2.1.17")))
            assertArrayEquals(bc,V2KeyEncoding.attestationChallenge(leaf(keys.biometricChain()).getExtensionValue("1.3.6.1.4.1.11129.2.1.17")))
            V2HardwareKeys.load(keys.id(),keys.transportPoint(),keys.biometricPoint())
            assertTrue(runCatching{V2HardwareKeys.load(keys.id(),keys.biometricPoint(),keys.transportPoint())}.isFailure)
            val input="RBA test-only transport proof".toByteArray()
            val raw=keys.transportProof(V2Enrollment.Proofs(input,byteArrayOf(1)))
            assertEquals(64,raw.size)
            val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
            val transport=ks.getKey(V2DeviceStore.transportAlias(keys.id()),null) as PrivateKey
            // Conscrypt TLS signs a prehashed CertificateVerify using this
            // exact non-exportable transport key. No biometric fallback.
            assertNull(transport.encoded)
            val digest=java.security.MessageDigest.getInstance("SHA-256").digest(input)
            val tlsSig=Signature.getInstance("NONEwithECDSA").apply{initSign(transport);update(digest)}.sign()
            assertTrue(Signature.getInstance("SHA256withECDSA").apply{initVerify(leaf(keys.transportChain()).publicKey);update(input)}.verify(tlsSig))
            val bio=ks.getKey(V2DeviceStore.biometricAlias(keys.id()),null) as PrivateKey
            assertNull(bio.encoded)
            val info=java.security.KeyFactory.getInstance("EC","AndroidKeyStore").getKeySpec(bio,android.security.keystore.KeyInfo::class.java)
            assertEquals(setOf(android.security.keystore.KeyProperties.DIGEST_SHA256),info.digests.toSet())
            // No CryptoObject has been authorized. An unauthenticated sign
            // must fail; a provider that returns a signature fails this test.
            val failure=runCatching{Signature.getInstance("SHA256withECDSA").apply{initSign(bio);update(input)}.sign()}.exceptionOrNull()
            assertNotNull("Unauthenticated biometric signing unexpectedly succeeded",failure)
            assertTrue("Expected authentication-related denial",generateSequence(failure){it.cause}.any{it is UserNotAuthenticatedException} || failure is java.security.SignatureException)
        } finally { V2HardwareKeys.deleteUnrecorded(keys.id(),keys.transportPoint(),keys.biometricPoint()) }
    }
}
