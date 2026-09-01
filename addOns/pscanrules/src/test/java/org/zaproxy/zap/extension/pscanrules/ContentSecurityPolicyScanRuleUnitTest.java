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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
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
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;

class ContentSecurityPolicyScanRuleUnitTest
        extends PassiveScannerTest<ContentSecurityPolicyScanRule> {

    // Note: This policy does not include sandbox, report-uri, or plugin-types
    private static final String REASONABLE_POLICY =
            "default-src 'self'; script-src 'self' "
                    + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                    + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                    + "fonts.gstatic.com; frame-ancestors 'none'; worker-src 'self'; form-action 'none'";
    private static final String REASONABLE_META_POLICY =
            "default-src 'self'; script-src 'self' "
                    + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                    + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                    + "fonts.gstatic.com; worker-src 'self'; form-action 'none'";

    @Override
    protected ContentSecurityPolicyScanRule createScanner() {
        return new ContentSecurityPolicyScanRule();
    }

    @Override
    public void shouldHaveExpectedAlertRefsInExampleAlerts() {
        // Given / When
        List<String> alertRefs = rule.getExampleAlerts().stream().map(Alert::getAlertRef).toList();
        // Then
        assertThat(
                alertRefs,
                equalTo(
                        IntStream.rangeClosed(1, 13)
                                // 10055-12 retired; skip contiguous check.
                                .filter(i -> i != 12)
                                .mapToObj(i -> "10055-" + i)
                                .toList()));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(7)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.SYSTEMIC.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A02_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
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
        assertThat(count, is(equalTo(12)));
        assertThat(countLows, is(equalTo(3L)));
        assertThat(countMediums, is(equalTo(9L)));
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
        assertThat(alertsRaised.size(), equalTo(5));
    }

    @Test
    void shouldAlertWhenCspContainsSyntaxIssues() {
        // Given
        HttpMessage msg = createHttpMessage("default-src: 'none'; report_uri /__cspreport__");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(5));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "Errors:\nDirective name default-src: contains characters outside the range ALPHA / DIGIT / \"-\"\nDirective name report_uri contains characters outside the range ALPHA / DIGIT / \"-\"\n"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));

        assertThat(
                alertsRaised.get(1).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(
                alertsRaised.get(1).getOtherInfo(),
                equalTo(
                        "The directive(s): frame-ancestors, form-action is/are among the directives that do not fallback to default-src."));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-13"));
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
        assertThat(alertsRaised.size(), equalTo(5));
        assertThat(
                alertsRaised.get(1).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(alertsRaised.get(1).getOtherInfo(), not(containsString("frame-ancestors")));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__; frame-ancestors 'none'"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-13"));
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
    void shouldAlertOnNoFallbackFrameAncestorsDirective() {
        // Given
        HttpMessage msg =
                createHttpMessage("frame-ancestors *; default-src 'self'; form-action 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The directive(s): frame-ancestors is/are among the directives that do not fallback to default-src."));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("frame-ancestors *; default-src 'self'; form-action 'none'"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-13"));
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
                                + "defined, or are overly broadly defined:\nconnect-src"));
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
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnReasonableMetaCspWithoutFrameAncestors() {
        // Given — meta CSPs cannot enforce frame-ancestors, so an otherwise-reasonable
        // meta policy still leaves framing unrestricted at the effective PolicyList layer
        HttpMessage msg = createHttpMessage();
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        + REASONABLE_META_POLICY
                        + "\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("frame-ancestors"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-13"));
    }

    @Test
    void shouldNotNpeOrAlertOnInvalidMetaCsp() {
        // Given
        HttpMessage msg = createHttpMessage();
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        // The comma here causes the parsing to fail and return null
                        + REASONABLE_META_POLICY
                        + ","
                        + "\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotFailToScanMetaWithMissingAttributes() {
        // Given
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        + REASONABLE_META_POLICY
                        + "\"><meta /></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldNotAlertWhenHeaderAndMetaBothPresentAndReasonable() {
        // Given — header provides frame-ancestors; meta is AND'd rather than flagged separately
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        + REASONABLE_META_POLICY
                        + "\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotAlertOnFrameAncestorsWhenHeaderRestrictsAndMetaHasWildcard() {
        // Given — meta FA is ignored for enforce queries; header FA still restricts via AND
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        + REASONABLE_META_POLICY
                        + "; frame-ancestors *"
                        + "\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then — Notices + Meta Policy Invalid Directive; no FA nofallback
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-11"));
        assertThat(
                alertsRaised.stream().noneMatch(a -> "10055-13".equals(a.getAlertRef())),
                is(equalTo(true)));
    }

    @Test
    void shouldAlertWhenAllEnforcePoliciesAllowUnsafeInline() {
        // Given — intersection still weak when every policy allows unsafe-inline
        HttpMessage msg =
                createHttpMessage(
                        "script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'");
        msg.getResponseHeader()
                .addHeader(
                        HttpFieldsNames.CONTENT_SECURITY_POLICY,
                        "script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().anyMatch(a -> "10055-5".equals(a.getAlertRef())),
                is(equalTo(true)));
    }

    @Test
    void shouldIncludeMultiPolicyOtherInfoAndUseFirstPolicyAsEvidence() {
        // Given
        String first = "script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'";
        String second = "default-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'";
        HttpMessage msg = createHttpMessage(first);
        msg.getResponseHeader().addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, second);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert unsafeInline =
                alertsRaised.stream()
                        .filter(a -> "10055-5".equals(a.getAlertRef()))
                        .findFirst()
                        .orElseThrow();
        assertThat(unsafeInline.getEvidence(), equalTo(first));
        assertThat(
                unsafeInline.getOtherInfo(),
                containsString("The response contained 2 Content-Security-Policy policies"));
        assertThat(unsafeInline.getOtherInfo(), containsString(first));
        assertThat(unsafeInline.getOtherInfo(), containsString(second));
    }

    @Test
    void shouldAndCommaSeparatedPoliciesInSingleHeader() {
        // Given — one header field value is a serialized CSP list
        HttpMessage msg = createHttpMessage(REASONABLE_POLICY + ", script-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then — reasonable half blocks unsafe-inline via AND
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportParsedPolicyCountForCommaSeparatedCspList() {
        // Given — one header text, two parsed policies, both allow unsafe-inline
        String cspList =
                "script-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none', "
                        + "default-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'";
        HttpMessage msg = createHttpMessage(cspList);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert unsafeInline =
                alertsRaised.stream()
                        .filter(a -> "10055-5".equals(a.getAlertRef()))
                        .findFirst()
                        .orElseThrow();
        assertThat(
                unsafeInline.getOtherInfo(),
                containsString("The response contained 2 Content-Security-Policy policies"));
        assertThat(unsafeInline.getOtherInfo(), containsString(cspList));
    }

    @Test
    void shouldNotAlertOnWildcardWhenSiblingPolicyRestrictsConnectSrc() {
        // Given
        HttpMessage msg =
                createHttpMessage(
                        "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'");
        msg.getResponseHeader()
                .addHeader(
                        HttpFieldsNames.CONTENT_SECURITY_POLICY,
                        "connect-src 'self'; default-src 'self'; form-action 'none'; frame-ancestors 'self'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertOnWildcardWhenAllPoliciesAllowWildcardConnectSrc() {
        // Given
        String policy =
                "connect-src *; default-src 'self'; form-action 'none'; frame-ancestors 'self'";
        HttpMessage msg = createHttpMessage(policy);
        msg.getResponseHeader().addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-4"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("connect-src"));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                containsString("The response contained 2 Content-Security-Policy policies"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"; sandbox allow-forms", "; frame-ancestors 'none'", "; report-uri /csp"})
    void shouldAlertOnMetaPolicyWithInvalidDirective(String invalidDirective) {
        // Given
        HttpMessage msg = createHttpMessage();
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\""
                        + REASONABLE_META_POLICY
                        + invalidDirective
                        + "\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().anyMatch(a -> "10055-11".equals(a.getAlertRef())),
                is(equalTo(true)));
        assertThat(
                alertsRaised.stream()
                        .filter(a -> "10055-3".equals(a.getAlertRef()))
                        .findFirst()
                        .orElseThrow()
                        .getOtherInfo(),
                containsString("ignored when delivered via a meta element"));
    }

    @Test
    void shouldNotAlertOnUnsafeHashesWhenSiblingPolicyLacksThem() {
        // Given
        HttpMessage msg =
                createHttpMessage(
                        "default-src 'self'; script-src 'unsafe-hashes'"
                                + " 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY=';"
                                + " form-action 'none'; frame-ancestors 'none'");
        msg.getResponseHeader()
                .addHeader(
                        HttpFieldsNames.CONTENT_SECURITY_POLICY,
                        "default-src 'self'; script-src 'self'; form-action 'none';"
                                + " frame-ancestors 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().noneMatch(a -> "10055-7".equals(a.getAlertRef())),
                is(equalTo(true)));
    }

    @Test
    void shouldAlertNoticesOnlyForHeaderWithSyntaxIssues() {
        // Given
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        String noisy = "default-src none; form-action 'none'; frame-ancestors 'none'";
        msg.getResponseHeader().addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, noisy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-3"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(noisy));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                containsString("missing the required quotes: 'none'"));
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

    @ParameterizedTest
    @CsvSource(
            value = {
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; trusted-types | Empty trusted-types directive allows all policy names",
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; require-trusted-types-for | The require-trusted-types-for directive requires a value"
            },
            delimiter = '|')
    void shouldAlertWhenTrustedTypesDirectivesMissingValues(String policy, String expectedError) {
        // Given
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString(expectedError));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-3"));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; trusted-types * | Wildcard policy names (*) permit any policy name",
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; trusted-types * 'allow-duplicates' | Wildcard policy names (*) permit any policy name"
            },
            delimiter = '|')
    void shouldAlertOnWildcardTrustedTypes(String policy, String expectedWarning) {
        // Given
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP: Notices"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString(expectedWarning));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-3"));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; trusted-types myPolicy 'allow-duplicates'",
                "default-src 'self'; frame-ancestors 'none'; form-action 'none'; trusted-types policy1 policy2 policy3"
            })
    void shouldNotAlertOnValidTrustedTypesPolicies(String policy) {
        // Given
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then - no alerts
        assertThat(alertsRaised, is(empty()));
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
        assertThat(alertsRaised.size(), equalTo(4));
        // Verify the specific alerts
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-13"));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP: Wildcard Directive"));
        assertThat(alertsRaised.get(1).getAlertRef(), equalTo("10055-4"));

        assertThat(alertsRaised.get(2).getName(), equalTo("CSP: script-src unsafe-inline"));
        assertThat(alertsRaised.get(2).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(2).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(2).getAlertRef(), equalTo("10055-5"));

        assertThat(alertsRaised.get(3).getName(), equalTo("CSP: style-src unsafe-inline"));
    }

    @Test
    void shouldNotAlertOnScriptUnsafeInlineWhenStrictDynamicPresent() {
        // Given — 'strict-dynamic' disables 'unsafe-inline' for scripts per CSP3
        HttpMessage msg =
                createHttpMessage(
                        "script-src 'strict-dynamic' 'unsafe-inline'; form-action 'none';"
                                + " frame-ancestors 'none'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().noneMatch(a -> "10055-5".equals(a.getAlertRef())),
                is(equalTo(true)));
    }

    @Test
    void shouldRaiseAlertWhenCspIncludesScriptUnsafeEval() {
        // Given
        HttpMessage msg = createHttpMessage("script-src 'unsafe-eval'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(4));
        // Verify the specific alerts
        assertThat(alertsRaised.get(3).getName(), equalTo("CSP: script-src unsafe-eval"));
        assertThat(alertsRaised.get(3).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(3).getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(alertsRaised.get(3).getAlertRef(), equalTo("10055-10"));
    }

    @Test
    void shouldNotAlertWhenSecondCspHasIssueButFirstIsReasonable() {
        // Given — browser AND: the reasonable policy blocks what the loose policy would allow
        HttpMessage msg =
                createHttpMessageWithReasonableCsp(HttpFieldsNames.CONTENT_SECURITY_POLICY);
        msg.getResponseHeader()
                .addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, "style-src 'unsafe-inline'");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
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
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-13"));

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
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(policy));
        assertThat(alertsRaised.get(0).getAlertRef(), equalTo("10055-13"));

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

    @Test
    void shouldUseGenericParamWhenHeaderUnparseableAndMetaProvidesEffectivePolicy() {
        // Given — header is present but unparseable (non-ASCII), so it never contributes to
        // enforcedPolicyTexts; only the meta policy is actually evaluated. The effective-policy
        // alerts' param must reflect that the header was unused, not point at the header itself.
        HttpMessage msg = createHttpMessage();
        msg.getResponseHeader().addHeader("Content-Security-Policy", "default-src ‘self’");
        msg.setResponseBody(
                "<html><head><meta http-equiv=\""
                        + HttpFieldsNames.CONTENT_SECURITY_POLICY
                        + "\" content=\"script-src 'unsafe-inline'\"></head></html>");
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert unsafeInline = findAlert("10055-5");
        assertThat(unsafeInline.getParam(), equalTo(HttpFieldsNames.CONTENT_SECURITY_POLICY));
        assertThat(unsafeInline.getEvidence(), equalTo("script-src 'unsafe-inline'"));
    }

    @Test
    void shouldAlertOnReasonableCspWhichIncludesPrefetchsrc() {
        // Given
        HttpMessage msg = createHttpMessage("", REASONABLE_POLICY + "; prefetch-src *");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                is(equalTo("Warnings:\nThe prefetch-src directive has been deprecated\n")));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // No form-action
                "default-src 'self'; script-src 'self' "
                        + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                        + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                        + "fonts.gstatic.com; frame-ancestors 'none'; worker-src 'self';",
                // No frame-ancestors
                "default-src 'self'; script-src 'self' "
                        + "storage.googleapis.com cdn.temasys.io cdn.tiny.cloud *.google-analytics.com; "
                        + "style-src 'self' *.googleapis.com; font-src 'self' data: *.googleapis.com "
                        + "fonts.gstatic.com; worker-src 'self'; form-action 'none'"
            })
    void shouldAlertWhenMissingRelevantDirectiveWithoutFallback(String policy) {
        // Given
        HttpMessage msg = createHttpMessage("", policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(equalTo(1)));
        assertThat(
                alertsRaised.get(0).getDescription(),
                is(
                        equalTo(
                                "The Content Security Policy fails to define one of the directives that has no "
                                        + "fallback. Missing/excluding them is the same as allowing anything.")));
        assertThat(
                alertsRaised.get(0).getName(),
                equalTo("CSP: Failure to Define Directive with No Fallback"));
    }

    @Test
    void shouldAlertOnUnsafeEvalWhenAllowedOnlyViaDefaultSrcFallback() {
        // Given — script-src omitted; default-src carries 'unsafe-eval', which governs via
        // the CSP fallback chain (Policy.getGoverningDirectiveForEffectiveDirective).
        String policy = "default-src 'unsafe-eval'; form-action 'none'; frame-ancestors 'none'";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert evalAlert = findAlert("10055-10");
        assertThat(evalAlert.getName(), equalTo("CSP: script-src unsafe-eval"));
        assertThat(evalAlert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(evalAlert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(evalAlert.getEvidence(), equalTo(policy));
    }

    @Test
    void shouldAlertOnUnsafeEvalWhenIntersectionReliesOnDefaultSrcFallback() {
        // Given — one policy names script-src, the other only default-src; intersection
        // still allows eval (PolicyList.allowsEval() == true).
        String first = "script-src 'unsafe-eval'; form-action 'none'; frame-ancestors 'none'";
        String second = "default-src 'unsafe-eval'; form-action 'none'; frame-ancestors 'none'";
        HttpMessage msg = createHttpMessage(first);
        msg.getResponseHeader().addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, second);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert evalAlert = findAlert("10055-10");
        assertThat(evalAlert.getName(), equalTo("CSP: script-src unsafe-eval"));
        assertThat(evalAlert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(evalAlert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(evalAlert.getEvidence(), equalTo(first));
    }

    @Test
    void shouldAlertOnUnsafeHashesWhenAllowedOnlyViaDefaultSrcFallback() {
        // Given — same fallback issue for 'unsafe-hashes' / 10055-7
        String policy =
                "default-src 'unsafe-hashes' 'sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY='; "
                        + "form-action 'none'; frame-ancestors 'none'";
        HttpMessage msg = createHttpMessage(policy);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert hashesAlert = findAlert("10055-7");
        assertThat(hashesAlert.getName(), equalTo("CSP: script-src unsafe-hashes"));
        assertThat(hashesAlert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(hashesAlert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(hashesAlert.getEvidence(), equalTo(policy));
    }

    @Test
    void shouldNotAlertOnUnsafeHashesWhenPoliciesHaveDisjointHashSets() {
        // Given — both policies contain 'unsafe-hashes' but list different hashes.
        // No concrete handler is allowed by every policy, so the intersection does not
        // effectively allow unsafe-hashes.
        String hashA = "sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY=";
        String hashB = "sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ=";
        HttpMessage msg = createHttpMessage(hashPolicy("script-src", hashA));
        msg.getResponseHeader()
                .addHeader(
                        HttpFieldsNames.CONTENT_SECURITY_POLICY, hashPolicy("script-src", hashB));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().filter(a -> "10055-7".equals(a.getAlertRef())).count(),
                equalTo(0L));
    }

    @Test
    void shouldNotAlertOnStyleUnsafeHashesWhenPoliciesHaveDisjointHashSets() {
        // Given — same disjoint-hash-set scenario for style-src / 10055-8
        String hashA = "sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY=";
        String hashB = "sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ=";
        HttpMessage msg = createHttpMessage(hashPolicy("style-src", hashA));
        msg.getResponseHeader()
                .addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, hashPolicy("style-src", hashB));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(
                alertsRaised.stream().filter(a -> "10055-8".equals(a.getAlertRef())).count(),
                equalTo(0L));
    }

    @Test
    void shouldAlertOnUnsafeHashesWhenIntersectingHashSetsAllowThem() {
        // Given — shared hash + keyword in every policy → intersection still permits
        // unsafe-hashes for that hash; 10055-7 is appropriate.
        String sharedHash = "sha256-jzgBGA4UWFFmpOBq0JpdsySukE1FrEN5bUpoK8Z29fY=";
        String extraHash = "sha256-xyz4zkCjuC3lZcD2UmnqDG0vurmq12W/XKM5Vd0+MlQ=";
        String first = hashPolicy("script-src", sharedHash);
        String second = hashPolicy("script-src", sharedHash, extraHash);
        HttpMessage msg = createHttpMessage(first);
        msg.getResponseHeader().addHeader(HttpFieldsNames.CONTENT_SECURITY_POLICY, second);
        // When
        scanHttpResponseReceive(msg);
        // Then
        Alert hashesAlert = findAlert("10055-7");
        assertThat(hashesAlert.getName(), equalTo("CSP: script-src unsafe-hashes"));
        assertThat(hashesAlert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(hashesAlert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(hashesAlert.getEvidence(), equalTo(first));
    }

    private Alert findAlert(String alertRef) {
        return alertsRaised.stream()
                .filter(a -> alertRef.equals(a.getAlertRef()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected " + alertRef + " alert"));
    }

    private static String hashPolicy(String directive, String... hashes) {
        StringBuilder sb =
                new StringBuilder("default-src 'self'; ")
                        .append(directive)
                        .append(" 'unsafe-hashes'");
        for (String hash : hashes) {
            sb.append(" '").append(hash).append('\'');
        }
        return sb.append("; form-action 'none'; frame-ancestors 'none'").toString();
    }

    private static HttpMessage createHttpMessageWithReasonableCsp(String cspHeaderName) {
        return createHttpMessage(cspHeaderName, REASONABLE_POLICY);
    }

    private static HttpMessage createHttpMessage(String cspPolicy) {
        return createHttpMessage(HttpFieldsNames.CONTENT_SECURITY_POLICY, cspPolicy);
    }

    private static HttpMessage createHttpMessage(String cspHeaderName, String cspPolicy) {
        HttpMessage msg = new HttpMessage();

        String header =
                !cspHeaderName.isEmpty() ? cspHeaderName : HttpFieldsNames.CONTENT_SECURITY_POLICY;

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
            msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        }
        return msg;
    }

    private static HttpMessage createHttpMessage() {
        HttpMessage msg = new HttpMessage();
        try {
            msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        } catch (HttpMalformedHeaderException e) {
            // Ignore
        }
        return msg;
    }
}
