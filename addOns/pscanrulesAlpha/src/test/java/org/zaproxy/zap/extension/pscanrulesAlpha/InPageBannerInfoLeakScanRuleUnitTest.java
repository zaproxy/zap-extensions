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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class InPageBannerInfoLeakScanRuleUnitTest
        extends PassiveScannerTest<InPageBannerInfoLeakScanRule> {

    private HttpMessage createMessage(String banner) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_FOUND);
        msg.setResponseBody("<html><body>" + banner + "</body></html>");
        return msg;
    }

    @Override
    protected InPageBannerInfoLeakScanRule createScanner() {
        return new InPageBannerInfoLeakScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfResponseIsRedirect() throws URIException {
        // Given
        HttpMessage msg = createMessage("");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.TEMPORARY_REDIRECT);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfResponseHasRelevanContent() throws URIException {
        // Given
        String squidBanner = "Squid/2.5.STABLE4";
        HttpMessage msg = createMessage(squidBanner);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Squid/2.5"));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasRelevantContentWithStatusOk() throws URIException {
        // Given - Default threshold (MEDIUM)
        String apacheBanner = "Apache/2.4.17";
        HttpMessage msg = createMessage(apacheBanner);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfThresholdLowResponseHasRelevantContentWithStatusOk()
            throws URIException {
        // Given
        String jettyBanner = "Jetty://9.4z-SNAPSHOT";
        HttpMessage msg = createMessage(jettyBanner);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Jetty://9.4"));
    }
}
