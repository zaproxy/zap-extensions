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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.network.HttpSenderImpl;

class HttpOnlySiteScanRuleUnitTest extends ActiveScannerTest<HttpOnlySiteScanRule> {

    @Override
    protected HttpOnlySiteScanRule createScanner() {
        return new HttpOnlySiteScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(311)));
        assertThat(wasc, is(equalTo(4)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getValue())));
    }

    @ParameterizedTest
    @CsvSource({"-1, -1", "80, -1", "443, -1", "8080, 8080"})
    @SuppressWarnings("try")
    void shouldAccessHttpsWithExpectedPort(int initialPort, int expectedPort) throws Exception {
        try (var senderImpl = new TestHttpSenderImpl()) {
            // Given
            rule.init(getHttpMessage(initialPort), parent);
            // When
            rule.scan();
            // Then
            assertThat(httpMessagesSent, hasSize(1));
            URI uri = httpMessagesSent.get(0).getRequestHeader().getURI();
            assertThat(uri.getScheme(), is(equalTo(HttpHeader.HTTPS)));
            assertThat(uri.getPort(), is(equalTo(expectedPort)));
        }
    }

    private static HttpMessage getHttpMessage(int port) throws Exception {
        HttpMessage msg = new HttpMessage();
        StringBuilder header = new StringBuilder();
        header.append("GET http://localhost");
        if (port != -1) {
            header.append(':').append(port);
        }
        header.append(" HTTP/1.1\r\n");
        msg.setRequestHeader(header.toString());
        return msg;
    }

    private static class TestHttpSenderImpl implements AutoCloseable {

        @SuppressWarnings("unchecked")
        TestHttpSenderImpl() {
            HttpSender.setImpl(mock(HttpSenderImpl.class));
        }

        @Override
        public void close() {
            HttpSender.setImpl(null);
        }
    }
}
