/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.llmheader;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpRequestHeader;

class HeaderAnonymizerTest {

    @Test
    void shouldAnonymizeSensitiveHeaders() throws Exception {
        // Given
        String headerStr =
                "GET / HTTP/1.1\r\n"
                        + "Host: example.com\r\n"
                        + "Authorization: Bearer secret\r\n"
                        + "Cookie: session=123\r\n"
                        + "User-Agent: TestAgent\r\n\r\n";
        HttpHeader header = new HttpRequestHeader(headerStr);

        // When
        Map<String, String> result = HeaderAnonymizer.anonymize(header, true);

        // Then
        assertThat(result.get("Authorization"), is("[REDACTED]"));
        assertThat(result.get("Cookie"), is("[REDACTED]"));
        assertThat(result.get("User-Agent"), is("TestAgent"));
    }

    @Test
    void shouldNotAnonymizeWhenDisabled() throws Exception {
        // Given
        String headerStr = "GET / HTTP/1.1\r\n" + "Authorization: Bearer secret\r\n\r\n";
        HttpHeader header = new HttpRequestHeader(headerStr);

        // When
        Map<String, String> result = HeaderAnonymizer.anonymize(header, false);

        // Then
        assertThat(result.get("Authorization"), is("Bearer secret"));
    }
}
