package io.github.burtvadr.rba.transport

import org.junit.Test
import org.junit.Assert.assertTrue

class V2OperationWireTest {
    @Test fun ownershipAndCancellation(){assertTrue(V2OperationWireChecks.run()>=20)}
}
