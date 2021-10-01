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
import static org.hamcrest.Matchers.is;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class StrictTransportSecurityScanRuleUnitTest
        extends PassiveScannerTest<StrictTransportSecurityScanRule> {

    private static final String STS_HEADER = "Strict-Transport-Security";
    private static final String HEADER_VALUE = "max-age=31536000"; // 1 year
    private static final String SHORT_VALUE = "max-age=86400";

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("https://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected StrictTransportSecurityScanRule createScanner() {
        return new StrictTransportSecurityScanRule();
    }

    @Test
    void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alerts

        // Given
        StrictTransportSecurityScanRule thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("Strict-Transport-Security Header"));
    }

    @Test
    void shouldNotRaiseAlertIfResponsIsNotHttps() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setSecure(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfResponseMissingHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(), equalTo("Strict-Transport-Security Header Not Set"));
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasWelformedHeaderAndValue() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, SHORT_VALUE);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfResponseHasMultipleHeaders() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, SHORT_VALUE);
        msg.getResponseHeader().addHeader(STS_HEADER, HEADER_VALUE);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo(
                        "Strict-Transport-Security Multiple Header Entries (Non-compliant with Spec)"));
    }

    @Test
    void shouldRaiseAlertIfResponseHasStsDisablingHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, "max-age=0");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Strict-Transport-Security Disabled"));
    }

    @Test
    void shouldRaiseAlertIfResponseHasStsHeaderWithBlankValue() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, "");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("Strict-Transport-Security Missing Max-Age (Non-compliant with Spec)"));
    }

    @Test
    void shouldRaiseAlertIfHeaderValueHasJunkContent() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, SHORT_VALUE + "”"); // Append curly quote
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("Strict-Transport-Security Malformed Content (Non-compliant with Spec)"));
    }

    @Test
    void shouldRaiseAlertIfHeaderValueHasImproperQuotes() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, "\"max-age=84600\""); // Quotes before max
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("Strict-Transport-Security Max-Age Malformed (Non-compliant with Spec)"));
    }

    @Test
    void shouldRaiseAlertIfThresholdLowNonSecureResponseWithHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setSecure(false);
        msg.getResponseHeader().addHeader(STS_HEADER, HEADER_VALUE);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("Strict-Transport-Security Header on Plain HTTP Response"));
    }

    @Test
    void shouldNotRaiseAlertIfThresholdLowNonSecureResponseNoHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getRequestHeader().setSecure(false);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfResponseContainsStsHeaderAndMeta() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(STS_HEADER, HEADER_VALUE);
        msg.setResponseBody(
                "<html><meta http-equiv=\"Strict-Transport-Security\" content=\"max-age=31536000\" /></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("Strict-Transport-Security Defined via META (Non-compliant with Spec)"));
    }

    @Test
    void shouldNotRaiseAlertIfThresholdNotLowRedirectSameDomain() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(301);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, "https://example.com/default/");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfThresholdLowRedirectSameDomain() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(301);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, "https://example.com/default/");
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(), equalTo("Strict-Transport-Security Header Not Set"));
    }

    @Test
    void shouldNotRaiseAlertIfThresholdNotLowRedirectRelativePath() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(301);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, "/default/");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfThresholdLowRedirectRelativePath() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(301);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, "/default/");
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(), equalTo("Strict-Transport-Security Header Not Set"));
    }

    @Test
    void shouldRaiseAlertIfThresholdNotLowRedirectCrossDomain() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setStatusCode(301);
        msg.getResponseHeader().addHeader(HttpHeader.LOCATION, "https://other.com/default/");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(), equalTo("Strict-Transport-Security Header Not Set"));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }
}
