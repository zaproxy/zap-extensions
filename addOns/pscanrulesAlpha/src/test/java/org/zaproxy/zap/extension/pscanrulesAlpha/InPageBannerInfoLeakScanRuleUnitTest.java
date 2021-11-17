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
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class InPageBannerInfoLeakScanRuleUnitTest
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
    void shouldNotRaiseAlertIfResponseIsRedirect() throws URIException {
        // Given
        HttpMessage msg = createMessage("");
        msg.getResponseHeader().setStatusCode(HttpStatusCode.TEMPORARY_REDIRECT);
        given(passiveScanData.isPage200(any())).willReturn(false);
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfResponseHasRelevanContent() throws URIException {
        // Given
        String squidBanner = "Squid/2.5.STABLE4";
        HttpMessage msg = createMessage(squidBanner);
        given(passiveScanData.isPage200(any())).willReturn(false);
        given(passiveScanData.isClientError(any())).willReturn(true);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Squid/2.5"));
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasRelevantContentWithStatusOk() throws URIException {
        // Given - Default threshold (MEDIUM)
        String apacheBanner = "Apache/2.4.17";
        HttpMessage msg = createMessage(apacheBanner);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        given(passiveScanData.isPage200(any())).willReturn(false);
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasRelevantContentWithCustomPage200() throws URIException {
        // Given - Default threshold (MEDIUM)
        String apacheBanner = "Apache/2.4.17";
        HttpMessage msg = createMessage(apacheBanner);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.TEMPORARY_REDIRECT);
        given(passiveScanData.isPage200(any())).willReturn(true);
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfThresholdLowResponseHasRelevantContentWithStatusOk()
            throws URIException {
        // Given
        String jettyBanner = "Jetty://9.4z-SNAPSHOT";
        HttpMessage msg = createMessage(jettyBanner);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        given(passiveScanData.isPage200(any())).willReturn(false);
        given(passiveScanData.isClientError(any())).willReturn(false);
        given(passiveScanData.isServerError(any())).willReturn(false);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Jetty://9.4"));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INFO_02_FINGERPRINT_WEB_SERVER.getValue())));
    }
}
