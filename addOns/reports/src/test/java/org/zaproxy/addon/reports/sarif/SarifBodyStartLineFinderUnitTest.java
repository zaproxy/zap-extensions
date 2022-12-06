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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.reports.sarif.SarifResult.SarifBody;

class SarifBodyStartLineFinderUnitTest {

    private SarifBodyStartLineFinder toTest;
    private SarifBody body;

    @BeforeEach
    void beforeEach() {
        toTest = new SarifBodyStartLineFinder();
        body = mock(SarifBody.class);
    }

    @Test
    void contentFoundInsideTextBodyResultsInCorrectLine() {
        /* prepare */
        String text = "Line1\nLine2\nLine3-Content\nLine4";
        when(body.getText()).thenReturn(text);

        /* execute */
        long found = toTest.findStartLine(body, "Line3-Content");

        /* test */
        assertEquals(3, found);
    }

    @Test
    void contentSubPartFoundInsideTextBodyResultsInCorrectLine() {
        /* prepare */
        String text = "Line1\nLine2-ContentXsubPartY\nLine3\nLine4";
        when(body.getText()).thenReturn(text);

        /* execute */
        long found = toTest.findStartLine(body, "subPart");

        /* test */
        assertEquals(2, found);
    }

    @Test
    void contentNotFoundInsideTextBodyResultsInLine0() {
        /* prepare */
        String text = "Line1\nLine2\nLine3-Content\nLine4";
        when(body.getText()).thenReturn(text);

        /* execute */
        long found = toTest.findStartLine(body, "Not found");

        /* test */
        assertEquals(0, found);
    }

    @Test
    void contentNullSoNotFoundInsideTextBodyResultsInLine0() {
        /* prepare */
        String text = null;
        when(body.getText()).thenReturn(text);

        /* execute */
        long found = toTest.findStartLine(body, "Not found");

        /* test */
        assertEquals(0, found);
    }

    @Test
    void contentSomethingNotFoundInsideNullBodyResultsInLine0() {
        /* prepare */
        String text = null;
        when(body.getText()).thenReturn(text);

        /* execute */
        long found = toTest.findStartLine(null, "Something");

        /* test */
        assertEquals(0, found);
    }
}
