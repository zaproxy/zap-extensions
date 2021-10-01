/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class PermissionsPolicyScanRuleUnitTest extends PassiveScannerTest<PermissionsPolicyScanRule> {

    private static final String MESSAGE_PREFIX = "pscanalpha.permissionspolicymissing.";
    private HttpMessage msg;

    @BeforeEach
    void before() throws Exception {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
    }

    @Override
    protected PermissionsPolicyScanRule createScanner() {
        return new PermissionsPolicyScanRule();
    }

    @Test
    void shouldRaiseAlertOnMissingHeaderHTML() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "name"));
    }

    @Test
    void shouldRaiseAlertOnMissingHeaderJavaScript() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/javascript");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "name"));
    }

    @Test
    void shouldNotRaiseAlertOnMissingHeaderOthers() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "application/json");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertOnAvailablePermissionsPolicyHeader() throws Exception {
        // Given
        msg.getResponseHeader().addHeader("Permissions-Policy", "vibrate 'none'");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/HTML");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnAvailableDeprecatedFeaturePolicyHeader() throws Exception {
        // Given
        msg.getResponseHeader().addHeader("Feature-Policy", "vibrate 'none'");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/HTML");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "deprecated.name"));
    }

    @Test
    void shouldNotRaiseAlertOnMissingHeaderRedirectMediumThreshold() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        msg.setResponseHeader("HTTP/1.1 301 Moved Permanently\r\n");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldRaiseAlertOnMissingHeaderRedirectLowThreshold() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        msg.setResponseHeader("HTTP/1.1 301 Moved Permanently\r\n");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "name"));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
    }
}
