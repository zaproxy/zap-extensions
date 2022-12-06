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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SarifHtmlToPlainTextConverterUnitTest {

    private SarifHtmlToPlainTextConverter toTest;

    @BeforeEach
    void beforeEach() {
        toTest = new SarifHtmlToPlainTextConverter();
    }

    @Test
    void convertToPlainTextAPlainTextIsKeptAsIs() {
        assertConvertToPlainText("entry1\nentry2", "entry1\nentry2");
    }

    @Test
    void convertToPlainTextMultilinesWithParagraphs() {
        assertConvertToPlainText("<p>entry1</p>\n<p>entry2</p>", "entry1\n\nentry2\n");
    }

    @Test
    void convertToPlainTextHTMLandBodyAreJustRemoved() {
        assertConvertToPlainText("<html><body>text1\ntext2</body></html>", "text1\ntext2");
    }

    @Test
    void convertToPlainTextbrSingleTagNoEndingJustRemoved() {
        assertConvertToPlainText("<br>text", "\ntext");
    }

    @Test
    void convertToPlainTextbrSingleTagwithEndingJustRemoved() {
        assertConvertToPlainText("<br/>text", "\ntext");
    }

    @Test
    void convertToPlainTextXYZTagNoClosingJustRemoved() {
        assertConvertToPlainText("<xyz>text", "text");
    }

    @Test
    void convertToPlainTextXYZTagOpeningAndClosingJustRemoved() {
        assertConvertToPlainText("<xyz>text</xyz>", "text");
    }

    @Test
    void convertToPlainTextXYTagZWithClosingTagsJustRemoved() {
        assertConvertToPlainText("<xyz/>text", "text");
    }

    @Test
    void convertToPlainTextNull() {
        assertConvertToPlainText(null, null);
    }

    void assertConvertToPlainText(String html, String wantedPlainText) {
        /* execute */
        String result = toTest.convertToPlainText(html);

        /* test */
        assertEquals(wantedPlainText, result);
    }
}
