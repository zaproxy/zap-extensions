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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

class SiteIsolationScanRuleTest extends PassiveScannerTest<SiteIsolationScanRule> {
    @Test
    void shouldRaiseCorpAlertGivenSiteIsNotIsolated() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldNotRaiseAlertGivenSiteIsIsolated() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertGivenSiteIsIsolatedWhenSuccessIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 400 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertGivenSiteIsIsolatedWhenSuccessAndIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertGivenSiteIsNotIsolatedWhenSuccessNotIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Content-Type: text/html\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertGivenSiteIsNotIsolatedWhenSuccessIdentifiedByCustomPage()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 400 OK\r\n" + "Content-Type: text/html\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(3));
    }

    @Test
    void shouldRaiseCorpAlertGivenResponseDoesntSendCorpHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldRaiseCorpAlertGivenCorpHeaderIsSetForSameSite() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-site\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldRaiseCorpAlertGivenCorpHeaderContentIsUnexpected() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: unexpected\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldRaiseCorpAlertCaseInsensitive() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: same-SITE\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldNotRaiseCorpAlertGivenCorpHeaderIsSetForCrossOrigin() throws Exception {
        // We consider that resource has been explicitly set to be shared.
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cross-Origin-Resource-Policy: cross-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseCorpAlertOnlyForSuccessfulQueries() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 500 Internal Server Error\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(false);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Access-Control-Allow-Origin", "access-control-allow-origin"})
    void shouldNotRaiseCorpAlertGivenCorsHeaderIsSet(String corsFieldName) throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + corsFieldName
                        + ": *\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertGivenCoepHeaderIsMissing() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/xml\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoepHeaderScanRule.HEADER));
    }

    @Test
    void shouldRaiseAlertGivenCoepHeaderIsNotExpectedValue() throws Exception {
        // Given
        HttpMessage msg = getCoepMessage("unsafe-none");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoepHeaderScanRule.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("unsafe-none"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"require-corp", "credentialless"})
    void shouldNotRaiseAlertGivenCoepHeaderIsAnExpectedValue(String directive) throws Exception {
        // Given
        HttpMessage msg = getCoepMessage(directive);
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    private static HttpMessage getCoepMessage(String directive)
            throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                """
                HTTP/1.1 200 OK\r
                Content-Type: text/html; charset=iso-8859-1\r
                Cross-Origin-Resource-Policy: same-origin\r
                Cross-Origin-Embedder-Policy: %s\r
                Cross-Origin-Opener-Policy: same-origin
                """
                        .formatted(directive));
        return msg;
    }

    @Test
    void shouldRaiseAlertGivenCoopHeaderIsMissing() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html;charset=utf-8\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n"
                        + "Cross-Origin-Embedder-Policy: require-corp\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(SiteIsolationScanRule.CoopHeaderScanRule.HEADER));
    }

    @Test
    void shouldRaiseAlertGivenCoopHeaderIsNotSameOrigin() throws Exception {
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
        given(passiveScanData.isSuccess(any())).willReturn(true);

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
    void shouldNotRaiseCoepOrCoopAlertGivenResourceIsNotAnHtmlOrXmlDocument() throws Exception {
        // Definition of Document: https://dom.spec.whatwg.org/#document
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertGivenNoHeaderContentTypeIsPresent() throws Exception {
        // If no header content-type is provided, it is browser-dependent.
        //        It will try to sniff the type.
        // There is a rule ContentTypeMissingScanRule
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Cross-Origin-Resource-Policy: same-origin\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertForReportingAPI() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html\r\n"
                        + "cross-origin-embedder-policy: require-corp;report-to=\"coep\"\r\n"
                        + "cross-origin-opener-policy: same-origin;report-to=\"coop\"\r\n"
                        + "Cross-Origin-Resource-Policy: same-origin;report-to=\"corp\"\r\n");
        given(passiveScanData.isSuccess(any())).willReturn(true);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(5)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> examples = rule.getExampleAlerts();
        // Then
        assertThat(examples.size(), is(equalTo(3)));
        Alert corp = examples.get(0);
        Alert coep = examples.get(1);
        Alert coop = examples.get(2);
        assertThat(corp.getAlertRef(), is(equalTo("90004-1")));
        assertThat(coep.getAlertRef(), is(equalTo("90004-2")));
        assertThat(coop.getAlertRef(), is(equalTo("90004-3")));
    }

    @Override
    protected SiteIsolationScanRule createScanner() {
        return new SiteIsolationScanRule();
    }
}
