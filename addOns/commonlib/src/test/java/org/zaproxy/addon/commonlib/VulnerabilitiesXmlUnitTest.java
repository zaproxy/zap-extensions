/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import java.io.InputStream;
import java.util.List;
import java.util.stream.IntStream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.zaproxy.zap.testutils.UrlTests;

/** Unit test that checks the references in the internal vulnerabilities data file. */
class VulnerabilitiesXmlUnitTest implements UrlTests {

    private static final String VULNERABILITIES_XML =
            "/org/zaproxy/addon/commonlib/internal/vulns/vulnerabilities.xml";

    @Test
    void shouldHaveValidReferences() throws Exception {
        // Given
        List<String> urls = readReferences();
        // When / Then
        shouldHaveValidUrls(urls);
    }

    private static List<String> readReferences() throws Exception {
        try (InputStream in =
                VulnerabilitiesXmlUnitTest.class.getResourceAsStream(VULNERABILITIES_XML)) {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
            NodeList references = doc.getElementsByTagName("reference");
            return IntStream.range(0, references.getLength())
                    .mapToObj(i -> references.item(i).getTextContent().trim())
                    .filter(url -> !url.isEmpty())
                    .distinct()
                    .toList();
        }
    }
}
