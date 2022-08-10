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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class Base64DisclosureUnitTest extends PassiveScannerTest<Base64Disclosure> {

    private static final String HEADER_CONTENT = "W/\"45cd-7MlSATHznbvb7qdGT+/VL6oqXM\"";

    @Override
    protected Base64Disclosure createScanner() {
        return new Base64Disclosure();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "ETag",
                "etag",
                "ETAG",
                "Authorization",
                "X-ChromeLogger-Data",
                "X-ChromePhp-Data"
            })
    void shouldNotAlertOnIgnoredHeader(String headerName) throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(headerName, HEADER_CONTENT);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnBase64ContentInHeader() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader("example", HEADER_CONTENT);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    private static HttpMessage createMessage() throws Exception {
        HttpMessage msg = new HttpMessage(new URI("https://example.com/", false));
        msg.setResponseHeader("HTTP/1.1 200 Ok\r\n");
        return msg;
    }
}
