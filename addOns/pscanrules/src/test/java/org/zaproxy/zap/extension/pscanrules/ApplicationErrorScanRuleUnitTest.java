/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.parosproxy.paros.network.HttpStatusCode.INTERNAL_SERVER_ERROR;
import static org.parosproxy.paros.network.HttpStatusCode.NOT_FOUND;
import static org.parosproxy.paros.network.HttpStatusCode.OK;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class ApplicationErrorScanRuleUnitTest extends PassiveScannerTest<ApplicationErrorScanRule> {
    private static final String URI = "https://www.example.com/test/";
    private static final String REQUEST_HEADER = format("GET %s HTTP/1.1", URI);

    @Override
    protected ApplicationErrorScanRule createScanner() {
        return new ApplicationErrorScanRule();
    }

    @Override
    public void setUpZap() throws Exception {
        super.setUpZap();

        Path xmlDir = Files.createDirectories(Paths.get(Constant.getZapHome(), "xml"));
        Path testFile = xmlDir.resolve("application_errors.xml");
        String content =
                "<?xml version=\"1.0\" standalone=\"no\"?>\n"
                        + "<!-- \n"
                        + "UnitTest File\n"
                        + "-->\n"
                        + "<Patterns>\n"
                        + "  <Pattern type=\"string\">Microsoft OLE DB Provider for ODBC Drivers</Pattern>\n"
                        + "  <Pattern type=\"regex\">(?i)Line\\s\\d+:\\sIncorrect\\ssyntax\\snear\\s'[^']*'</Pattern>\n"
                        + "</Patterns>";
        Files.write(testFile, content.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ERRH_02_STACK.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ERRH_02_STACK.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ERRH_02_STACK.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        Alert alert = alerts.get(0);
        Map<String, String> tags = alert.getTags();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(alert.getTags().size(), is(equalTo(5)));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.WSTG_V42_ERRH_02_STACK.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    void shouldRaiseAlertIfResponseCodeIsInternalServerErrorLow()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(INTERNAL_SERVER_ERROR));
        given(passiveScanData.isPage500(any())).willReturn(true);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo("HTTP/1.1 500"));
        assertThat(result.getPluginId(), equalTo(90022));
        assertThat(result.getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(result.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(result.getUri(), equalTo(URI));
    }

    @Test
    void shouldRaiseAlertIfResponseCodeIsInternalServerErrorMed()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(INTERNAL_SERVER_ERROR));
        given(passiveScanData.isPage500(any())).willReturn(true);
        // When
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo("HTTP/1.1 500"));
        assertThat(result.getPluginId(), equalTo(90022));
        assertThat(result.getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(result.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(result.getUri(), equalTo(URI));
    }

    @Test
    void shouldNotRaiseAlertIfResponseCodeIsInternalServerErrorHigh()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(INTERNAL_SERVER_ERROR));
        given(passiveScanData.isPage500(any())).willReturn(true);
        // When
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseCodeIsNotFound() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(NOT_FOUND));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(true);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseCodeOkAndEmptyBody() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseCodeOkAndNoEvidenceDetected()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody(
                "<html>" + "<div>" + "here a body with no evidence" + "</div>" + "</html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertForResponseCodeOkAndStringEvidenceDetected()
            throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "Microsoft OLE DB Provider for ODBC Drivers";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody("<html>" + "<div>" + expectedEvidence + "</div>" + "</html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    @Test
    void shouldRaiseAlertForResponseCodeOkAndEvidenceDetectedWithMatcher()
            throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "Line 1024: Incorrect syntax near 'login'";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody("<html>" + "<div>" + expectedEvidence + "</div>" + "</html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    @Test
    void shouldRaiseAlertForResponseCodeOkAndCustomPayloadDetected()
            throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "customPayloadString";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody("<html>" + "<div>" + expectedEvidence + "</div>" + "</html>");
        ApplicationErrorScanRule.setPayloadProvider(() -> Arrays.asList(expectedEvidence));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    @Test
    void shouldNotRaiseAlertForResponseCodeOkAndCustomPayloadNotDetected()
            throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "customPayloadString";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody("<html>" + "<div>" + expectedEvidence + "</div>" + "</html>");
        ApplicationErrorScanRule.setPayloadProvider(() -> Arrays.asList("notDetectedString"));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertForResponseCodeOkAndFilePayloadDetected()
            throws HttpMalformedHeaderException {
        // Given
        // String from standard XML file
        String expectedEvidence = "Microsoft OLE DB Provider for ODBC Drivers";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody("<html>" + "<div>" + expectedEvidence + "</div>" + "</html>");
        ApplicationErrorScanRule.setPayloadProvider(() -> Arrays.asList(expectedEvidence));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    @Test
    void shouldNotRaiseAlertForResponseCodeOkAndContentTypeWebAssemblyWhenFilePayloadPresent()
            throws HttpMalformedHeaderException {
        // Given
        // String from standard XML file
        String expectedEvidence = "Microsoft OLE DB Provider for ODBC Drivers";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "application/wasm");
        msg.setResponseBody(expectedEvidence);
        ApplicationErrorScanRule.setPayloadProvider(() -> Arrays.asList(expectedEvidence));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static void validateAlert(Alert alert) {
        assertThat(alert.getPluginId(), equalTo(90022));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getUri(), equalTo(URI));
    }

    private static String createResponseHeader(int code) {
        return format("HTTP/1.1 %d\r\n", code);
    }
}
