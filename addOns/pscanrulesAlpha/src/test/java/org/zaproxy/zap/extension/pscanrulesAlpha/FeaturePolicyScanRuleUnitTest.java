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
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class FeaturePolicyScanRuleUnitTest extends PassiveScannerTest<FeaturePolicyScanRule> {

    private static final String MESSAGE_PREFIX = "pscanalpha.featurepolicymissing.";
    private HttpMessage msg;

    @BeforeEach
    public void before() throws Exception {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
    }

    @Override
    protected FeaturePolicyScanRule createScanner() {
        return new FeaturePolicyScanRule();
    }

    @Test
    public void shouldRaiseAlertOnMissingFeaturePolicyHTML() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "name"));
    }

    @Test
    public void shouldRaiseAlertOnMissingFeaturePolicyJavaScript() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/javascript");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
    }

    @Test
    public void shouldNotRaiseAlertOnMissingFeaturePolicyOthers() throws Exception {
        // Given
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "application/json");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertOnAvailableFeaturePolicy() throws Exception {
        // Given
        msg.getResponseHeader().addHeader("Feature-Policy", "vibrate 'none'");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/HTML");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertOnMissingFeaturePolicyRedirectMediumThreshold()
            throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.MEDIUM);
        msg.setResponseHeader("HTTP/1.1 301 Moved Permanently\r\n");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldRaiseAlertOnMissingFeaturePolicyRedirectLowThreshold() throws Exception {
        // Given
        rule.setAlertThreshold(Plugin.AlertThreshold.LOW);
        msg.setResponseHeader("HTTP/1.1 301 Moved Permanently\r\n");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(MESSAGE_PREFIX + "name"));
    }
}
