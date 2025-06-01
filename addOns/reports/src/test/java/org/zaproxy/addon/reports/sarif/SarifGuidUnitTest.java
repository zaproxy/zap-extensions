/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class SarifGuidUnitTest {

    @Test
    void createForTaxaResultsInGUIDStringWithExpectedLenghtOf36() {
        /* prepare */
        String identifier = "i.am.short";

        SarifTaxonomy taxonomy = Mockito.mock(SarifTaxonomy.class);

        /* execute */
        SarifGuid result = SarifGuid.createForTaxa(identifier, taxonomy);

        /* test */
        assertEquals(36, result.getGuid().length());
    }

    @Test
    void createForTaxaCalledMultipletTimesResultsAlwaysInSameGUIDString() {
        /* prepare */
        String identifier = "this.is.my.test.name";
        Set<String> resultSet = new HashSet<>();
        SarifTaxonomy taxonomy = Mockito.mock(SarifTaxonomy.class);

        /* execute */
        for (int i = 0; i < 10; i++) {
            SarifGuid result = SarifGuid.createForTaxa(identifier, taxonomy);
            resultSet.add(result.getGuid());
        }

        /* test */
        assertEquals(1, resultSet.size());
    }

    @Test
    void createForToolcomponentCalledMultipletTimesResultsAlwaysInSameGUIDString() {
        /* prepare */
        String identifier = "this.is.my.test.name";
        Set<String> resultSet = new HashSet<>();
        SarifTaxonomy taxonomy = Mockito.mock(SarifTaxonomy.class);

        /* execute */
        for (int i = 0; i < 10; i++) {
            SarifGuid result = SarifGuid.createForTaxa(identifier, taxonomy);
            resultSet.add(result.getGuid());
        }

        /* test */
        assertEquals(1, resultSet.size());
    }

    @Test
    void createCweGuidCalledMultipletTimesResultsAlwaysInSameGUIDString() {
        /* prepare */
        int identifier = 79;
        Set<String> resultSet = new HashSet<>();

        /* execute */
        for (int i = 0; i < 10; i++) {
            SarifGuid result = SarifGuid.createCweGuid(identifier);
            resultSet.add(result.getGuid());
        }

        /* test */
        assertEquals(1, resultSet.size());
    }

    @Test
    void createCweGuidsForCwe1ToCwe255ResultsAlwaysInDifferentGUIDString() {
        /* prepare */
        Set<String> resultSet = new HashSet<>();

        /* execute */
        for (int i = 1; i < 255; i++) {
            SarifGuid result = SarifGuid.createCweGuid(i);
            boolean notAlreadyContainedInSet = resultSet.add(result.getGuid());

            /* test */
            assertTrue(
                    notAlreadyContainedInSet,
                    "guid:"
                            + result.getGuid()
                            + " was already contained in set, means duplicate detected!");
        }
    }
}
