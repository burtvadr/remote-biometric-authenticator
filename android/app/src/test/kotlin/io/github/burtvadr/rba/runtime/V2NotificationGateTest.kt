package io.github.burtvadr.rba.runtime

import org.junit.Assert.assertEquals
import org.junit.Test

class V2NotificationGateTest {
    @Test fun oneShotForegroundHandoff(){assertEquals(24,V2NotificationGateChecks.run())}
}
