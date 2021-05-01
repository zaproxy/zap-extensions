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
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class ApplicationErrorScanRuleUnitTest extends PassiveScannerTest<ApplicationErrorScanRule> {
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
    public void shouldRaiseAlertIfResponseCodeIsInternalServerErrorLow()
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
    public void shouldRaiseAlertIfResponseCodeIsInternalServerErrorMed()
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
    public void shouldNotRaiseAlertIfResponseCodeIsInternalServerErrorHigh()
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
    public void shouldNotRaiseAlertIfResponseCodeIsNotFound() throws HttpMalformedHeaderException {
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
    public void shouldNotRaiseAlertIfResponseCodeOkAndEmptyBody()
            throws HttpMalformedHeaderException {
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
    public void shouldNotRaiseAlertIfResponseCodeOkAndNoEvidenceDetected()
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
    public void shouldRaiseAlertForResponseCodeOkAndStringEvidenceDetected()
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
    public void shouldRaiseAlertForResponseCodeOkAndEvidenceDetectedWithMatcher()
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
    public void shouldRaiseAlertForResponseCodeOkAndCustomPayloadDetected()
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
    public void shouldNotRaiseAlertForResponseCodeOkAndCustomPayloadNotDetected()
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
    public void shouldRaiseAlertForResponseCodeOkAndFilePayloadDetected()
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
    public void
            shouldNotRaiseAlertForResponseCodeOkAndContentTypeWebAssemblyWhenFilePayloadPresent()
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
