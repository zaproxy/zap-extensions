/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class ServerHeaderInfoLeakScanRuleUnitTest
        extends PassiveScannerTest<ServerHeaderInfoLeakScanRule> {

    private static final String SERVER = "Server";

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected ServerHeaderInfoLeakScanRule createScanner() {
        return new ServerHeaderInfoLeakScanRule();
    }

    @Test
    public void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alerts

        // Given
        ServerHeaderInfoLeakScanRule thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("HTTP Server Response Header"));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasNoRelevantHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfResponseHasRelevantHeader() throws URIException {
        // Given
        String apacheHeader = "Apache/2.4.1 (Unix)";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(SERVER, apacheHeader);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertEquals(apacheHeader, alertsRaised.get(0).getEvidence());
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasRelevantContentButNoVersion() throws URIException {
        // Given - Default threshold (MEDIUM)
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(SERVER, "Apache");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfThresholdLowResponseHasRelevantContentButNoVersion()
            throws URIException {
        // Given
        String bareApacheHeader = "Apache";
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(SERVER, bareApacheHeader);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertEquals(bareApacheHeader, alertsRaised.get(0).getEvidence());
    }
}
