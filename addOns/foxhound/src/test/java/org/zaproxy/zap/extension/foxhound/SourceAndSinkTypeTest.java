package org.zaproxy.zap.extension.foxhound;

import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;
import org.zaproxy.zap.testutils.TestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class SourceAndSinkTypeTest  extends TestUtils {

    public void testLoadingSourceSinkFile() {
        assertEquals(10, FoxhoundConstants.ALL_SOURCES.size());
    }

}
