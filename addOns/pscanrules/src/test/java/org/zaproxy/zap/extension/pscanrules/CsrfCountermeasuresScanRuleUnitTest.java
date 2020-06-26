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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class CsrfCountermeasuresScanRuleUnitTest
        extends PassiveScannerTest<CsrfCountermeasuresScanRule> {

    private ExtensionAntiCSRF extensionAntiCSRFMock;
    private List<String> antiCsrfTokenNames;
    private HttpMessage msg;

    @BeforeEach
    public void before() throws URIException {
        antiCsrfTokenNames = new ArrayList<>();
        antiCsrfTokenNames.add("token");
        antiCsrfTokenNames.add("csrfToken");

        extensionAntiCSRFMock = mock(ExtensionAntiCSRF.class);
        Mockito.lenient()
                .when(extensionAntiCSRFMock.getAntiCsrfTokenNames())
                .thenReturn(antiCsrfTokenNames);

        rule.setExtensionAntiCSRF(extensionAntiCSRFMock);
        rule.setCsrfIgnoreList("");
        rule.setCSRFIgnoreAttName("");
        rule.setCSRFIgnoreAttValue("");

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Override
    protected CsrfCountermeasuresScanRule createScanner() {
        return new CsrfCountermeasuresScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfThereIsNoHTML() {
        // Given
        msg.setResponseBody("no html");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertIfThereIsNoForm() {
        // Given
        msg.setResponseBody("<html><head></head><body><p>no form</p></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertIfFormHasNoParent() {
        // Given
        msg.setResponseBody(
                "<form id=\"no_csrf_token\"><input type=\"text\"/><input type=\"submit\"/></form>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldRaiseAlertIfThereIsNoCSRFTokenFound() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"no_csrf_token\"><input type=\"text\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 1);
        assertEquals(alertsRaised.get(0).getWascId(), 9);
        assertEquals(alertsRaised.get(0).getEvidence(), "<form id=\"no_csrf_token\">");
    }

    @Test
    public void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithFirstKnownCSRFTokenUsingName() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"><input type=\"text\" name=\"token\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithAKnownCSRFTokenUsingId() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"><input type=\"text\" id=\"token\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldNotRaiseAlertWhenThereIsOnlyOneFormWithSecondKnownCSRFTokenUsingName() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body><form id=\"form_name\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

    @Test
    public void shouldRaiseOneAlertForOneFormWhenSecondFormHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"second_form\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "<form id=\"first_form\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(alertsRaised.get(0).getEvidence(), "<form id=\"second_form\">");
    }

    @Test
    public void shouldRaiseOneAlertForOneFormWhenFirstFormOfTwoHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"first_form\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "<form id=\"second_form\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(alertsRaised.get(0).getEvidence(), "<form id=\"second_form\">");
    }

    @Test
    public void shouldRaiseTwoAlertsForTwoFormsWhenOneOfThreeHasAKnownCSRFToken() {
        // Given
        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"zeroth_form\" action=\"someaction\"><input type=\"text\" name=\"zero\"/><input type=\"submit\"/></form>"
                        + "<form id=\"first_form\"><input type=\"text\" name=\"csrfToken\"/><input type=\"submit\"/></form>"
                        + "<form id=\"second_form\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(2, alertsRaised.size());
        assertEquals(
                alertsRaised.get(0).getEvidence(),
                "<form id=\"zeroth_form\" action=\"someaction\">");
        assertEquals(alertsRaised.get(1).getEvidence(), "<form id=\"second_form\">");
    }

    @Test
    public void shouldNotRaiseAlertWhenFormIdIsOnCsrfIgnoreList() {
        // Given
        rule.setCsrfIgnoreList("ignoredName,otherName");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form id=\"ignoredName\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldNotRaiseAlertWhenFormNameIsOnCsrfIgnoreList() {
        // Given
        rule.setCsrfIgnoreList("ignoredName,otherName");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"otherName\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseInfoAlertWhenFormAttributeIsOnCsrfAttributeIgnoreList() {
        // Given
        rule.setCSRFIgnoreAttName("data-no-csrf");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
    }

    @Test
    public void shouldRaiseInfoAlertWhenFormAttributeAndValueMatchRuleConfig() {
        // Given
        rule.setCSRFIgnoreAttName("data-no-csrf");
        rule.setCSRFIgnoreAttValue("data-no-csrf");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" data-no-csrf=\"data-no-csrf\"><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
    }

    @Test
    public void shouldRaiseLowAlertWhenFormAttributeAndRuleConfigMismatch() {
        // Given
        rule.setCSRFIgnoreAttName("ignore");

        msg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
        assertEquals(Alert.RISK_LOW, alertsRaised.get(0).getRisk());
    }

    @Test
    public void shouldNotRaiseAlertWhenThresholdHighAndMessageOutOfScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(false);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertWhenThresholdHighAndMessageInScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(true);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertWhenThresholdMediumAndMessageOutOfScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(false);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void shouldRaiseAlertWhenThresholdLowAndMessageOutOfScope() throws URIException {
        // Given
        rule.setCSRFIgnoreAttName("ignore");
        HttpMessage msg = createScopedMessage(false);
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(1, alertsRaised.size());
    }

    private HttpMessage createScopedMessage(boolean isInScope) throws URIException {
        HttpMessage newMsg =
                new HttpMessage() {
                    @Override
                    public boolean isInScope() {
                        return isInScope;
                    }
                };
        newMsg.getRequestHeader().setURI(new URI("http://", "localhost", "/", ""));
        newMsg.setResponseBody(
                "<html><head></head><body>"
                        + "<form name=\"someName\" data-no-csrf><input type=\"text\" name=\"name\"/><input type=\"submit\"/></form>"
                        + "</body></html>");
        return newMsg;
    }
}
