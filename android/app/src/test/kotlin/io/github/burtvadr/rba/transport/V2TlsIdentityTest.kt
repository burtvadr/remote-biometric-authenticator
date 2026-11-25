package io.github.burtvadr.rba.transport

import org.junit.Assert.assertEquals
import org.junit.Test
class V2TlsIdentityTest {
    @Test fun exactPinsAndMutualTls(){assertEquals(13,V2TlsIdentityChecks.run())}
}
