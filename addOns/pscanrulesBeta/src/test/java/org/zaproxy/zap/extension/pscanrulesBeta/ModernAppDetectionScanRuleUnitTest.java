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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Unit test for ModernAppDetectionScanRule
 *
 * @see ModernAppDetectionScanRule
 */
public class ModernAppDetectionScanRuleUnitTest
        extends PassiveScannerTest<ModernAppDetectionScanRule> {

    @Override
    protected ModernAppDetectionScanRule createScanner() {
        return new ModernAppDetectionScanRule();
    }

    @Test
    public void shouldNotRaiseAlertWithBasicHtml() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head></head><body><H1>Nothing to see here...</H1></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertWithHashHref() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html><head></head><body><a href=\"#\">Link</a></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("<a href=\"#\">Link</a>"));
    }

    @Test
    public void shouldNotRaiseAlertWithFragmentHref() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html><head></head><body><a href=\"#blah\">Link</a></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAlertWithSelfTarget() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head></head><body><a href=\"link\" target=\"_self\">Link</a></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                is("<a href=\"link\" target=\"_self\">Link</a>"));
    }

    @Test
    public void shouldRaiseAlertWithEmptyHref() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("<html><head></head><body><a href=\"\">Link</a></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("<a href=\"\">Link</a>"));
    }

    @Test
    public void shouldRaiseAlertWithScriptsInBodyButNoLinks() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head></head><body><script src=\"/script.js\"></script></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("<script src=\"/script.js\"></script>"));
    }

    @Test
    public void shouldRaiseAlertWithScriptsInHeadButNoLinks() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head><script src=\"/script.js\"></script></head><body></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("<script src=\"/script.js\"></script>"));
    }

    @Test
    public void shouldRaiseAlertWithNoScript() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head><script src=\"/script.js\"></script></head><body><a href=\"link\">link</a><noscript>You need to enable JavaScript to run this app.</noscript></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                is("<noscript>You need to enable JavaScript to run this app.</noscript>"));
    }
}
