package io.github.burtvadr.rba.keystore

import org.junit.Test

class V2AliasReclamationTest {
    @Test fun exactNamespaceAndInventory(){
        val keep="1".repeat(32);val orphan="2".repeat(32)
        val provisional="rba-v2-provisional-12345678-1234-1234-1234-123456789abc"
        val names=listOf("rba-v2-$keep-transport","rba-v2-$keep-biometric","rba-v2-$orphan-transport","rba-v2-$orphan-biometric",provisional,"rba-v2-$orphan-other","rba-v2-${"0".repeat(32)}-transport","rba-v2-provisional-invalid","rba-v1-$orphan-transport","unrelated",provisional)
        check(V2AliasReclamation.unrecorded(names,setOf(keep))==listOf("rba-v2-$orphan-transport","rba-v2-$orphan-biometric",provisional).sorted())
        check(V2AliasReclamation.unrecorded(names,setOf(keep,orphan))==listOf(provisional))
        check(V2AliasReclamation.unrecorded(emptyList(),setOf(keep)).isEmpty())
        check(runCatching{V2AliasReclamation.unrecorded(names,setOf("not-an-id"))}.isFailure)
        check(runCatching{V2AliasReclamation.unrecorded(names,setOf("0".repeat(32)))}.isFailure)
    }
}
