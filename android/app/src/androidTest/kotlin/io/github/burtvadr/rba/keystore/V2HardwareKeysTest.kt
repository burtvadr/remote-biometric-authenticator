package io.github.burtvadr.rba.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.burtvadr.rba.protocol.V2Enrollment
import io.github.burtvadr.rba.session.V2DeviceStore
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.UUID
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

    /** Level 1 probe: local key metadata and the negative biometric gate,
     * without requesting attestation. No persisted RBA credential or trust. */
    @Test fun level1UnattestedBiometricKeyRejectsUnauthenticatedSigning() {
        val ks=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        val alias="rba-level1-test-biometric-${UUID.randomUUID()}"
        check(!ks.containsAlias(alias))
        try {
            val builder=KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(false)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .setUserAuthenticationValidWhileOnBody(false)
            if(Build.VERSION.SDK_INT>=30) builder.setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG)
            else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            KeyPairGenerator.getInstance("EC","AndroidKeyStore").apply{initialize(builder.build())}.generateKeyPair()
            val key=ks.getKey(alias,null) as PrivateKey
            assertNull(key.encoded)
            val cert=ks.getCertificate(alias) as X509Certificate
            assertNull(cert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17"))
            val info=KeyFactory.getInstance("EC","AndroidKeyStore").getKeySpec(key,KeyInfo::class.java)
            assertEquals(KeyProperties.ORIGIN_GENERATED,info.origin)
            assertEquals(256,info.keySize)
            assertEquals(KeyProperties.PURPOSE_SIGN,info.purposes)
            assertEquals(setOf(KeyProperties.DIGEST_SHA256),info.digests.toSet())
            assertTrue(info.isUserAuthenticationRequired)
            assertTrue(info.isUserAuthenticationRequirementEnforcedBySecureHardware)
            @Suppress("DEPRECATION")
            val perUse=info.userAuthenticationValidityDurationSeconds
            // Keystore2 implementations can report zero when AUTH_TIMEOUT is
            // absent. The modern generator uses zero for auth-per-operation;
            // the legacy getter documents -1. Neither permits a positive window.
            // This metadata check is not a substitute for the negative signing
            // probe below. No production key inspection is changed here.
            assertTrue("Expected per-operation authentication; reported duration=$perUse",
                perUse == -1 || (Build.VERSION.SDK_INT >= 30 && perUse == 0))
            if(Build.VERSION.SDK_INT>=31) assertTrue(info.securityLevel in setOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,KeyProperties.SECURITY_LEVEL_STRONGBOX))
            else {
                @Suppress("DEPRECATION")
                val hardware=info.isInsideSecureHardware
                assertTrue(hardware)
            }
            if(Build.VERSION.SDK_INT>=30) assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG,info.userAuthenticationType)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            val challenge=ByteArray(32).apply{SecureRandom().nextBytes(this)}
            val failure=runCatching{Signature.getInstance("SHA256withECDSA").apply{initSign(key);update(challenge)}.sign()}.exceptionOrNull()
            assertNotNull("Unauthenticated biometric signing unexpectedly succeeded",failure)
            assertTrue("Expected authentication-related denial",generateSequence(failure){it.cause}.any{it is UserNotAuthenticatedException} || failure is java.security.SignatureException)
        } finally {
            if(ks.containsAlias(alias)) ks.deleteEntry(alias)
            assertFalse(ks.containsAlias(alias))
        }
    }

}
