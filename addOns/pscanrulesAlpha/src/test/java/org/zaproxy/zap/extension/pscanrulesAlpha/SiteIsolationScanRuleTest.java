/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

class SiteIsolationScanRuleTest extends PassiveScannerTest<SiteIsolationScanRule> {
    @Test
    public void shouldNotRaiseAlertGivenSiteIsIsolated() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseAlertGivenSiteIsIsolatedWhenSuccessIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 400 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseAlertGivenSiteIsIsolatedWhenSuccessAndIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldRaiseCorpAlertGivenResponseDoesntSendCorpHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CorpHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void shouldRaiseCorpAlertGivenCorpHeaderIsSetForSameSite() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-site\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CorpHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same-site"));
    }

    @Test
    public void shouldRaiseCorpAlertGivenCorpHeaderContentIsUnexpected() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: unexpected\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CorpHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("unexpected"));
    }

    @Test
    public void shouldRaiseCorpAlertCaseInsensitive() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-SITE\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CorpHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same-SITE"));
    }

    @Test
    public void shouldNotRaiseCorpAlertGivenCorpHeaderIsSetForCrossOrigin() throws Exception {
        // We consider that resource has been explicitly set to be shared.
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: cross-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldRaiseCorpAlertOnlyForSuccessfulQueries() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 500 Internal Server Error\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseCorpAlertGivenCorsHeaderIsSet() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Access-Control-Allow-Origin: *\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldRaiseAlertGivenCoepHeaderIsMissing() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/xml\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoepHeaderScanRule.HEADER));
    }

    @Test
    public void shouldRaiseAlertGivenCoepHeaderIsNotEqualsToRequireCorp() throws Exception {
        // Ref: https://html.spec.whatwg.org/multipage/origin.html#the-headers
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=iso-8859-1\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: unsafe-none\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoepHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("unsafe-none"));
    }

    @Test
    public void shouldRaiseAlertGivenCoopHeaderIsMissing() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html;charset=utf-8\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoopHeaderScanRule.HEADER));
    }

    @Test
    public void shouldRaiseAlertGivenCoopHeaderIsNotSameOrigin() throws Exception {
        // Ref: https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policies
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoopHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same-origin-allow-popups"));
    }

    @Test
    public void shouldNotRaiseCoepOrCoopAlertGivenResourceIsNotAnHtmlOrXmlDocument()
            throws Exception {
        // Definition of Document: https://dom.spec.whatwg.org/#document
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseAlertGivenNoHeaderContentTypeIsPresent() throws Exception {
        // If no header content-type is provided, it is browser-dependent.
        //        It will try to sniff the type.
        // There is a rule ContentTypeMissingScanRule
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Cross-Origin-Resource-Policy: same-origin\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseAlertForReportingAPI() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html\r\n"
                        + "cross-origin-embedder-policy: require-corp;report-to=\"coep\"\r\n"
                        + "cross-origin-opener-policy: same-origin;report-to=\"coop\"\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin;report-to=\"corp\"\r\n");
        given(passiveScanData.isPage200(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Override
    protected SiteIsolationScanRule createScanner() {
        return new SiteIsolationScanRule();
    }
}
