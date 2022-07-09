/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class ContentSecurityPolicyScanRuleUnitTest
        extends PassiveScannerTest<ContentSecurityPolicyScanRule> {

    private static final String REASONABLE_POLICY =
            "default-src 'self'; script-src 'self' "
                    + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                    + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                    + "fonts.gstatic.com; frame-ancestors 'none'; worker-src 'self'; form-action 'none'";
    private static final String HTTP_HEADER_CSP = "Content-Security-Policy";

    @Override
    protected ContentSecurityPolicyScanRule createScanner() {
        return new ContentSecurityPolicyScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(693)));
        assertThat(wasc, is(equalTo(15)));
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

    @Test
    void shouldReturnExpectedExampleAlerts() {
        // Given / When
        int count = rule.getExampleAlerts().size();
        long countLows =
                rule.getExampleAlerts().stream()
                        .filter(alert -> Alert.RISK_LOW == alert.getRisk())
                        .count();
        long countMediums =
                rule.getExampleAlerts().stream()
                        .filter(alert -> Alert.RISK_MEDIUM == alert.getRisk())
                        .count();
        // Then
        assertThat(count, is(equalTo(9)));
        assertThat(countLows, is(equalTo(3L)));
        assertThat(countMediums, is(equalTo(6L)));
    }

    @Test
    void shouldNotRaiseAlertOnNonHtmlAtMediumThreshold() {
        // Given
        HttpMessage msg = createHttpMessage("report-uri /__cspreport__");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "image/png");
        // When
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertOnNonHtmlAtLowThreshold() {
        // Given
        HttpMessage msg = createHttpMessage("report-uri /__cspreport__");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "image/png");
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(4));
    }

    @Test
    void shouldAlertWhenCspContainsSyntaxIssues() {
        // Given
        HttpMessage msg = createHttpMessage("default-src: 'none'; report_uri /__cspreport__");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(4));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "Warnings:\nUnrecognized directive default-src:\nUnrecognized directive report_uri\n"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(1).getOtherInfo(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), are not "
                                + "defined, or are overly broadly defined: \nscript-src, style-src, img-src, "
                                + "connect-src, frame-src, frame-ancestors, font-src, media-src, object-src, "
                                + "manifest-src, worker-src, prefetch-src, form-action\n\nThe directive(s): "
                                + "frame-ancestors, form-action are among the directives that do not fallback "
                                + "to default-src, missing/excluding them is the same as allowing anything."));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-4"));
    }

    @Test
    void shouldNotAlertOnValidSyntaxWhenCspContainsSyntaxIssues() {
        // Given
        HttpMessage msg =
                createHttpMessage(
                        "default-src: 'none'; report_uri /__cspreport__; frame-ancestors 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(4));
        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(1).getOtherInfo(), not(containsString("frame-ancestors")));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__; frame-ancestors 'none'"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-4"));
    }

    @Test
    void shouldAlertWithCspWarningNoticesWhenApplicable() {
        // Given
        HttpMessage msg = createHttpMessage("default-src none; report-to csp-endpoint ");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "Warnings:\nThis host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.\n"));

        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src none; report-to csp-endpoint"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-3"));
    }

    @Test
    void shouldAlertOnWildcardFrameAncestorsDirective() {
        // Given
        HttpMessage msg =
                createHttpMessage("frame-ancestors *; default-src 'self'; form-action 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), are not "
                                + "defined, or are overly broadly defined: \nframe-ancestors"
                                + "\n\nThe directive(s): frame-ancestors are among the directives that do not "
                                + "fallback to default-src, missing/excluding them is the same as allowing anything."));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("frame-ancestors *; default-src 'self'; form-action 'none'"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));
    }

    @Test
    void shouldAlertOnWildcardConnectSourceDirective() {
        // Given
        HttpMessage msg =
                createHttpMessage(
                        "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), are not "
                                + "defined, or are overly broadly defined: \nconnect-src"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));
    }

    @Test
    void shouldNotAlertOnReasonableCsp() {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(HTTP_HEADER_CSP);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"; require-trusted-types-for 'script'", "; trusted-types 'none'"})
    void shouldNotAlertOnReasonableCspWithTrustedTypes(String policyAddition) {
        // Given
        HttpMessage msg = createHttpMessage("", REASONABLE_POLICY + policyAddition);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertWithCspWarningNoticesWhenApplicableAndIgnoreTrustedTypes() {
        // Given
        String policy = "default-src none; report-to csp-endpoint; require-trusted-types 'script'";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "Warnings:\nThis host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.\n"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-3"));
    }

    @ParameterizedTest
    @CsvSource(value = {"X-Content-Security-Policy, 1", "X-WebKit-CSP, 2"})
    void shouldRaiseAlertOnLegacyCspHeader(String input, String alertRef) {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(input);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: " + input));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-" + alertRef));
    }

    @Test
    void shouldRaiseAlertWhenCspIncludesScriptUnsafeInline() {
        // Given
        HttpMessage msg = createHttpMessage("script-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(3));
        // Verify the specific alerts
        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-5"));

        assertThat(alertsRaised.get(2).getName(), equalTo("CSP: style-src unsafe-inline"));
    }

    @Test
    void shouldRaiseAlertWhenCspIncludesStyleUnsafeInline() {
        // Given
        HttpMessage msg = createHttpMessage("style-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(3));
        // Verify the specific alerts
        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-5"));

        assertThat(alertsRaised.get(2).getName(), equalTo("CSP: style-src unsafe-inline"));
    }

    @Test
    void shouldRaiseAlertOnSecondCspHasIssueFirstDoesNot() {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(HTTP_HEADER_CSP);
        msg.getResponseHeader().addHeader(HTTP_HEADER_CSP, "style-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(3));
        // Verify the specific alerts
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("style-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getEvidence(), equalTo("style-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-5"));

        assertThat(alertsRaised.get(2).getName(), equalTo("CSP: style-src unsafe-inline"));
        assertThat(alertsRaised.get(2).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(2).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(2).getEvidence(), equalTo("style-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(2).getAlertRef(), equalTo("10055-6"));
    }

    @Test
    void shouldRaiseAlertOnUnsafeInDefaultSrc() {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(HTTP_HEADER_CSP);
        msg.getResponseHeader().addHeader(HTTP_HEADER_CSP, "default-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(3));
        // Verify the specific alerts
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("default-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getEvidence(), equalTo("default-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-5"));

        assertThat(alertsRaised.get(2).getName(), equalTo("CSP: style-src unsafe-inline"));
        assertThat(alertsRaised.get(2).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(2).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(2).getEvidence(), equalTo("default-src 'unsafe-inline'"));
        assertThat(alertsRaised.get(2).getAlertRef(), equalTo("10055-6"));
    }

    @Test
    void shouldRaiseAlertOnUnsafeHashesInScriptSrc() {
        // Given
        String policy =
                "default-src 'self'; script-src 'unsafe-hashes' 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        // Verify the specific alerts
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-hashes"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-7"));
    }

    @Test
    void shouldRaiseAlertOnUnsafeHashesInStyleSrc() {
        // Given
        String policy =
                "default-src 'self'; style-src 'unsafe-hashes' 'sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ='";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        // Verify the specific alerts
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: style-src unsafe-hashes"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-8"));
    }

    @Test
    void shouldRaiseAlertWhenPolicyContainsNonasciiCharacters() {
        // Given
        String policy = "\"default-src ‘self’ 'unsafe-eval' 'unsafe-inline' www.example.net;\"";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        // Verify the specific alerts
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Malformed Policy (Non-ASCII)"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "A non-ASCII character was encountered while attempting to parse the policy, thus rendering it invalid (no further evaluation occurred). The following invalid characters were collected: ‘’"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-9"));
    }

    private HttpMessage createHttpMessageWithReasonableCsp(String cspHeaderName) {
        return createHttpMessage(cspHeaderName, REASONABLE_POLICY);
    }

    private HttpMessage createHttpMessage(String cspPolicy) {
        return createHttpMessage(HTTP_HEADER_CSP, cspPolicy);
    }

    private HttpMessage createHttpMessage(String cspHeaderName, String cspPolicy) {
        HttpMessage msg = new HttpMessage();

        String header = !cspHeaderName.isEmpty() ? cspHeaderName : HTTP_HEADER_CSP;

        try {
            msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

            msg.setResponseBody("<html></html>");
            msg.setResponseHeader(
                    "HTTP/1.1 200 OK\r\n"
                            + "Server: Apache-Coyote/1.1\r\n"
                            + header
                            + ":"
                            + cspPolicy
                            + "\r\n"
                            + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                            + "Content-Length: "
                            + msg.getResponseBody().length()
                            + "\r\n");
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }
        return msg;
    }
}
