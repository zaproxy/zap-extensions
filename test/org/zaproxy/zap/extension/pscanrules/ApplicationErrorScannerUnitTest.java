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

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static java.lang.String.format;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.parosproxy.paros.network.HttpStatusCode.*;

@SuppressWarnings("Duplicates")
public class ApplicationErrorScannerUnitTest extends PassiveScannerTest<ApplicationErrorScanner> {
    private static final String URI = "https://www.example.com/test/";
    private static final String REQUEST_HEADER = format("GET %s HTTP/1.1", URI);

    @Override
    protected ApplicationErrorScanner createScanner() {
        return new ApplicationErrorScanner();
    }

    @Test
    public void shouldRaiseAlertIfResponseCodeIsInternalServerError() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(INTERNAL_SERVER_ERROR));
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo("HTTP/1.1 500"));
        validateAlert(result);
    }

    @Test
    public void shouldNotRaiseAlertIfResponseCodeIsNotFound() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(NOT_FOUND));
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseCodeOkAndEmptyBody() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseCodeOkAndNoEvidenceDetected() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        msg.setResponseBody("<html>" +
                "<div>" +
                "here a body with no evidence" +
                "</div>" +
                "</html>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertForResponseCodeOkAndStringEvidenceDetected() throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "Microsoft OLE DB Provider for ODBC Drivers";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        msg.setResponseBody("<html>" +
                "<div>" +
                expectedEvidence +
                "</div>" +
                "</html>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    @Test
    public void shouldRaiseAlertForResponseCodeOkAndEvidenceDetectedWithMatcher() throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "Line 1024: Incorrect syntax near 'login'";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(OK));
        msg.setResponseBody("<html>" +
                "<div>" +
                expectedEvidence +
                "</div>" +
                "</html>");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
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
