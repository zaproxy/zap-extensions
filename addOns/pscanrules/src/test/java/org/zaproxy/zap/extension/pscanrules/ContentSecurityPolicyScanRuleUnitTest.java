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
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ContentSecurityPolicyScanRuleUnitTest
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
    public void shouldNotRaiseAlertOnNonHtmlAtMediumThreshold() {
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
    public void shouldRaiseAlertOnNonHtmlAtLowThreshold() {
        // Given
        HttpMessage msg = createHttpMessage("report-uri /__cspreport__");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "image/png");
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
    }

    @Test
    public void shouldAlertWhenCspContainsSyntaxIssues() {
        // Given
        HttpMessage msg = createHttpMessage("default-src: 'none'; report_uri /__cspreport__");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(
                        "Errors:\n"
                                + "1:12: Expecting directive-value but found U+003A (:). Non-ASCII and non-printable characters must be percent-encoded.\n"
                                + "1:22: Unrecognised directive-name: \"report\".\n"
                                + "1:28: Expecting directive-value but found U+005F (_). Non-ASCII and non-printable characters must be percent-encoded.\n"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(1).getDescription(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), are not "
                                + "defined, or are overly broadly defined: \nscript-src, script-src-elem, script-src-attr"
                                + ", style-src, style-src-elem, style-src-attr, img-src, connect-src, frame-src, "
                                + "frame-ancestors, font-src, media-src, object-src, manifest-src, worker-src, prefetch-src, form-action"
                                + "\n\nThe directive(s): frame-ancestors, form-action are among the directives that do "
                                + "not fallback to default-src, missing/excluding them is the same as allowing anything."));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldAlertWithCspWarningNoticesWhenApplicable() {
        // Given
        HttpMessage msg = createHttpMessage("default-src none; report-to csp-endpoint ");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(
                        "Warnings:\n"
                                + "1:13: This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.\n"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src none; report-to csp-endpoint"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldRaiseAlertAtInfoRiskWhenOnlyInformationalNotices() {
        // Given
        HttpMessage msg = createHttpMessage("report-uri /__cspreport__");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldIntersectMultipleCspHeaders() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; script-src www.example.com\r\n"
                        + "Content-Security-Policy: script-src *; style-src *:80\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), "
                                + "are not defined, or are overly broadly defined: \nframe-ancestors, form-action"
                                + "\n\nThe directive(s): frame-ancestors, form-action are among the directives that "
                                + "do not fallback to default-src, missing/excluding them is the same as allowing anything."));

        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src 'self'; script-src www.example.com"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The response contained multiple CSP headers, "
                                + "these were merged (intersected) into a single policy for evaluation:\ndefault-src 'self'; "
                                + "script-src www.example.com; style-src\nNote: The highlighting and evidence for this alert "
                                + "may be inaccurate due to these multiple headers."));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldNotIntersectMultipleCspHeadersIfOneHasReportUri()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; script-src www.example.com\r\n"
                        + "Content-Security-Policy: script-src *; style-src *:80; report-uri /report/ \r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), "
                                + "are not defined, or are overly broadly defined: \nframe-ancestors, form-action"
                                + "\n\nThe directive(s): frame-ancestors, form-action are among the directives that "
                                + "do not fallback to default-src, missing/excluding them is the same as allowing anything."));

        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src 'self'; script-src www.example.com"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The response contained multiple CSP headers, one or more of them contained "
                                + "a report-uri directive and therefore they could not be merged. "
                                + "The first identified header/policy was analyzed."));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldAlertOnWildcardFrameAncestorsDirective() {
        // Given
        HttpMessage msg =
                createHttpMessage("frame-ancestors *; default-src 'self'; form-action 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(
                alertsRaised.get(0).getDescription(),
                equalTo(
                        "The following directives either allow wildcard sources (or ancestors), are not "
                                + "defined, or are overly broadly defined: \nframe-ancestors"
                                + "\n\nThe directive(s): frame-ancestors are among the directives that do not "
                                + "fallback to default-src, missing/excluding them is the same as allowing anything."));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("frame-ancestors *; default-src 'self'; form-action 'none'"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldNotAlertOnReasonableCsp() {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(HTTP_HEADER_CSP);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"X-Content-Security-Policy", "X-WebKit-CSP"})
    public void shouldRaiseAlertOnLegacyCspHeader(String input) {
        // Given
        HttpMessage msg = createHttpMessageWithReasonableCsp(input);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: " + input));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldRaiseAlertWhenCspIncludesScriptUnsafeInline() {
        // Given
        HttpMessage msg = createHttpMessage("script-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        // Verify the specific alert
        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    public void shouldRaiseAlertWhenCspIncludesStyleUnsafeInline() {
        // Given
        HttpMessage msg = createHttpMessage("style-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        // Verify the specific alert
        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: style-src unsafe-inline"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
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
