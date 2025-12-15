/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Method;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class InsecureHttpMethodScanRuleUnitTest extends ActiveScannerTest<InsecureHttpMethodScanRule> {

    private static final String PATH = "/test/";
    private static final List<String> PUT_PATCH = List.of("PUT", "PATCH");
    private static final List<String> API_CONTENT_TYPES = List.of("json", "xml");

    @Override
    protected InsecureHttpMethodScanRule createScanner() {
        return new InsecureHttpMethodScanRule();
    }

    @Override
    protected boolean isIgnoreAlertsRaisedInSendReasonableNumberOfMessages() {
        return true;
    }

    private static Stream<Arguments> providePutPatchApiCombinations(AlertThreshold threshold) {
        return PUT_PATCH.stream()
                .flatMap(
                        method ->
                                API_CONTENT_TYPES.stream()
                                        .map(ct -> Arguments.of(method, ct, threshold)));
    }

    private static Stream<Arguments> providePutPatchApiCombosLowThreshold() {
        return providePutPatchApiCombinations(AlertThreshold.LOW);
    }

    private static Stream<Arguments> providePutPatchApiCombosMediumAndHighThreshold() {
        return Stream.concat(
                providePutPatchApiCombinations(AlertThreshold.MEDIUM),
                providePutPatchApiCombinations(AlertThreshold.HIGH));
    }

    private static Stream<Arguments> providePutPatchHtmlCombinations(AlertThreshold threshold) {
        return PUT_PATCH.stream().map(method -> Arguments.of(method, "html", threshold));
    }

    private static Stream<Arguments> providePutPatchHtmlCombosLowThreshold() {
        return providePutPatchHtmlCombinations(AlertThreshold.LOW);
    }

    private static Stream<Arguments> providePutPatchHtmlCombosMediumAndHighThreshold() {
        return Stream.concat(
                providePutPatchHtmlCombinations(AlertThreshold.MEDIUM),
                providePutPatchHtmlCombinations(AlertThreshold.HIGH));
    }

    @ParameterizedTest
    @MethodSource("providePutPatchApiCombosMediumAndHighThreshold")
    void shouldNotRaiseAlertsForPutOrPatchMethodsIfReturnJsonOrXmlAtHighOrMediumThreshold(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new OkayPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @MethodSource("providePutPatchApiCombosLowThreshold")
    void shouldRaiseAlertsForPutOrPatchMethodsIfReturnJsonOrXmlAtLowThreshold(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new OkayPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(
                alert.getOtherInfo(),
                is(
                        "The OPTIONS method disclosed the following enabled HTTP methods for this resource: [%s]"
                                .formatted(method)));
    }

    @ParameterizedTest
    @MethodSource("providePutPatchHtmlCombosLowThreshold")
    void shouldRaiseAlertForPutOrPatchMethodsIfReturnHtmlLowThresholdForbiddenStatus(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new ForbiddenPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Insecure HTTP Method - " + method));

        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertOtherInfoByThreshold(method, threshold, alert);
    }

    @ParameterizedTest
    @MethodSource("providePutPatchHtmlCombosMediumAndHighThreshold")
    void shouldRaiseAlertForPutOrPatchMethodsIfReturnHtmlAtHighOrMediumThresholdForbiddenStatus(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new ForbiddenPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    private static void assertOtherInfoByThreshold(
            String method, AlertThreshold threshold, Alert alert) {
        switch (threshold) {
            case LOW -> {
                assertThat(
                        alert.getOtherInfo(),
                        is(
                                equalTo(
                                        "The OPTIONS method disclosed the following enabled HTTP methods for this resource: [%s]"
                                                .formatted(method))));
            }
            default -> { // MEDIUM or HIGH
                assertThat(
                        alert.getOtherInfo(),
                        is(
                                equalTo(
                                        "Received response code 403 for potentially insecure HTTP method. This suggests it is enabled or supported but some control prevented us from actually using it.\n\nSee the discussion on stackexchange: https://security.stackexchange.com/questions/21413/how-to-exploit-http-methods, for understanding REST operations see https://www.restapitutorial.com/lessons/httpmethods.html")));
            }
        }
    }

    @ParameterizedTest
    @MethodSource("providePutPatchHtmlCombosMediumAndHighThreshold")
    void shouldNotRaiseAlertForPutOrPatchMethodsIfReturnHtmlMediumOrHighThresholdOkStatus(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new OkayPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @ParameterizedTest
    @MethodSource("providePutPatchHtmlCombosLowThreshold")
    void shouldRaiseAlertForPutOrPatchMethodsIfReturnHtmlLowThresholdOkStatus(
            String method, String contentType, AlertThreshold threshold) throws Exception {
        // Given
        HttpMessage message = getHttpMessage(PATH);
        nano.addHandler(new OkayPutPatchNanoServerHandler(method, contentType));

        rule.init(message, parent);
        rule.setAlertThreshold(threshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), equalTo("Insecure HTTP Method - " + method));

        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertOtherInfoByThreshold(method, threshold, alert);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(749)));
        assertThat(wasc, is(equalTo(45)));
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getValue())));
    }

    private static class OkayPutPatchNanoServerHandler
            extends SpecificStatusPutPatchNanoServerHandler {
        OkayPutPatchNanoServerHandler(String method, String contentType) {
            super(method, contentType, Status.OK);
        }
    }

    private static class ForbiddenPutPatchNanoServerHandler
            extends SpecificStatusPutPatchNanoServerHandler {
        ForbiddenPutPatchNanoServerHandler(String method, String contentType) {
            super(method, contentType, Status.FORBIDDEN);
        }
    }

    private static class SpecificStatusPutPatchNanoServerHandler extends NanoServerHandler {

        String contentType;
        String method;
        Status status;

        SpecificStatusPutPatchNanoServerHandler(String method, String contentType, Status status) {
            super(PATH);
            this.method = method;
            this.contentType = contentType;
            this.status = status;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            Response response = newFixedLengthResponse("");

            if (session.getMethod().equals(Method.OPTIONS)) {
                response.addHeader("Allow", method);
                return response;
            }

            if (session.getMethod().equals(Method.PUT)
                    || session.getMethod().equals(Method.PATCH)) {
                response.setMimeType("text/" + contentType);
                response.setStatus(status);
                return response;
            }
            consumeBody(session);
            return response;
        }
    }
}
