/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class CacheControlScanRuleUnitTest extends PassiveScannerTest<CacheControlScanRule> {

    @Override
    protected CacheControlScanRule createScanner() {
        return new CacheControlScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(1)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ATHN_06_CACHE_WEAKNESS.getValue())));
    }

    @Test
    void shouldNotAlertOnHttpRequest() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotAlertOnHttpsAllPresentCacheRequest() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldIgnoreEmptyHttpsResponses() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertOnHttpsMissingNoCacheRequest() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-store, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alert.getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alert.getEvidence(), equalTo("no-store, must-revalidate"));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldAlertOnHttpsMissingNoStoreCacheRequest() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no-cache, must-revalidate"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldAlertOnHttpsMissingMustRevalidateCacheRequest() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-store, no-cache\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no-store, no-cache"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldAlertOnHttpsRedirectLowCacheRequest() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Location: http://www.example.org/test2\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"MEDIUM", "HIGH"})
    void shouldNotAlertOnHttpsRedirectMedHighCacheRequest(AlertThreshold threshold)
            throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(threshold);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Location: http://www.example.org/test2\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnHttpsErrorLowCacheRequest() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"MEDIUM", "HIGH"})
    void shouldNotAlertOnHttpsErrorMedHighCacheRequest(AlertThreshold threshold)
            throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(threshold);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnttpsJavaScriptLowCacheRequest() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.js HTTP/1.1");
        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/javascript;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"MEDIUM", "HIGH"})
    void shouldNotAlertOnHttpsJavaScriptMedHighCacheRequest(AlertThreshold threshold)
            throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(threshold);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.js HTTP/1.1");
        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/javascript;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnHttpsCssLowCacheRequest() throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(AlertThreshold.LOW);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.css HTTP/1.1");
        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/css;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"MEDIUM", "HIGH"})
    void shouldNotAlertHttpsCssMedHighCacheRequest(AlertThreshold threshold)
            throws HttpMalformedHeaderException {
        // Given
        rule.setAlertThreshold(threshold);
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.css HTTP/1.1");
        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/css;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }
}
