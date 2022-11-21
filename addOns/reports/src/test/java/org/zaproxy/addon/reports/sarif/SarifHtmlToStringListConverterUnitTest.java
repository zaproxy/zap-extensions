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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SarifHtmlToStringListConverterUnitTest {

    private SarifHtmlToStringListConverter toTest;

    @BeforeEach
    void beforeEach() {
        toTest = new SarifHtmlToStringListConverter();
    }

    @Test
    void convertToListNull() {
        assertConvertToPlainText(null, Collections.emptyList());
    }

    @Test
    void convertToListEmptyString() {
        assertConvertToPlainText("", Collections.emptyList());
    }

    @Test
    void convertSinglePlainTextLineAsOneElement() {
        assertConvertToPlainText(
                "http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html",
                Arrays.asList("http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html"));
    }

    @Test
    void convertThreeMultiPlainTextLinesAsThreElement() {
        assertConvertToPlainText(
                "http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html\nOther\nLast",
                Arrays.asList(
                        "http://seclists.org/lists/webappsec/2002/Oct-Dec/0111.html",
                        "Other",
                        "Last"));
    }

    @Test
    void convertToListContainsPtaggedEntriesOneLine() {
        assertConvertToPlainText("<p>entry1</p><p>entry2</p>", Arrays.asList("entry1", "entry2"));
        assertConvertToPlainText(
                "\"<p>http://projects.webappsec.org/Cross-Site-Scripting</p><p>http://cwe.mitre.org/data/definitions/79.html</p>\"",
                Arrays.asList(
                        "http://projects.webappsec.org/Cross-Site-Scripting",
                        "http://cwe.mitre.org/data/definitions/79.html"));
    }

    @Test
    void convertToListContainsPtaggedEntriesMultiLine() {
        assertConvertToPlainText("<p>entry1</p>\n<p>entry2</p>", Arrays.asList("entry1", "entry2"));
        assertConvertToPlainText(
                "\n\n<p>entry1</p>\n<p>entry2</p><p>entry3</p>",
                Arrays.asList("entry1", "entry2", "entry3"));
    }

    @Test
    void convertToListContainsPtaggedEntriesTrimmed() {
        assertConvertToPlainText(
                "<p>entry1     </p>\n<p>     entry2</p>", Arrays.asList("entry1", "entry2"));
    }

    @Test
    void convertToListContainsPtaggedEntriesWithOtherContentAround() {
        assertConvertToPlainText(
                "<html><body>somethingelse<p>entry1</p><p>entry2</p>Followed by other things</body></html>",
                Arrays.asList("entry1", "entry2"));
        assertConvertToPlainText(
                "<html>\n<body>\nsomethingelse<p>entry1</p>\n<p>entry2</p>\nFollowed by other things\n</body>\n</html>",
                Arrays.asList("entry1", "entry2"));
    }

    void assertConvertToPlainText(String html, List<String> expectedList) {
        /* execute */
        List<String> result = toTest.convertToList(html);

        /* test */
        assertEquals(expectedList, result);
    }
}
