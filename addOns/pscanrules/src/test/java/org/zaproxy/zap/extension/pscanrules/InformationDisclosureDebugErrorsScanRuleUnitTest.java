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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class InformationDisclosureDebugErrorsScanRuleUnitTest
        extends PassiveScannerTest<InformationDisclosureDebugErrorsScanRule> {
    private static final String URI = "https://www.example.com/";
    private static final String DEFAULT_ERROR_MESSAGE = "Internal Server Error";
    private static final List<String> DEBUG_ERRORS =
            Arrays.asList(
                    DEFAULT_ERROR_MESSAGE,
                    "There seems to have been a problem with the",
                    "This error page might contain sensitive information because ASP.NET",
                    "PHP Error");

    @TempDir Path testFolder;

    @Override
    protected InformationDisclosureDebugErrorsScanRule createScanner() {
        InformationDisclosureDebugErrorsScanRule scanner =
                new InformationDisclosureDebugErrorsScanRule();

        try {
            Path errorFile = testFolder.resolve("debug-error-messages.txt");
            Files.write(errorFile, DEBUG_ERRORS, Charset.forName("UTF-8"));
            scanner.setDebugErrorFile(errorFile);
        } catch (IOException e) {
            throw new RuntimeException("Could not write debug error messages file.", e);
        }

        return scanner;
    }

    protected HttpMessage createHttpMessageWithRespBody(String responseBody)
            throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        return msg;
    }

    @Test
    public void shouldFindDebugErrorsFile() {
        // Given
        String debugErrorFilePath = "/xml/debug-error-messages.txt";
        // When
        URL debugErrorFile = getClass().getResource(debugErrorFilePath);
        // Then
        assertThat(debugErrorFile, notNullValue());
    }

    @Test
    public void alertsIfDebugErrorsDisclosed() throws HttpMalformedHeaderException {
        for (int i = 0; i < DEBUG_ERRORS.size(); i++) {
            String debugError = DEBUG_ERRORS.get(i);
            String responseBody = "<html>" + debugError + "</html>";

            HttpMessage msg = createHttpMessageWithRespBody(responseBody);

            scanHttpResponseReceive(msg);

            assertThat(alertsRaised.size(), equalTo(i + 1));

            Alert alert = alertsRaised.get(i);
            assertThat(alert.getMessage(), equalTo(msg));
            assertThat(alert.getUri(), equalTo(URI));
            assertThat(alert.getRisk(), equalTo(Alert.RISK_LOW));
            assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
            assertThat(alert.getCweId(), equalTo(200));
            assertThat(alert.getWascId(), equalTo(13));
            assertThat(alert.getEvidence(), equalTo(debugError));
        }
    }

    @Test
    public void alertsIfMixedCaseDebugErrorsDisclosed() throws HttpMalformedHeaderException {
        int expectedAlerts = 0;

        // Test the normal error message
        HttpMessage msg =
                createHttpMessageWithRespBody("<html>" + DEFAULT_ERROR_MESSAGE + "</html>");

        scanHttpResponseReceive(msg);

        expectedAlerts++;
        assertThat(alertsRaised.size(), equalTo(expectedAlerts));
        Alert alert = alertsRaised.get(expectedAlerts - 1);
        assertThat(alert.getCweId(), equalTo(200));
        assertThat(alert.getWascId(), equalTo(13));
        assertThat(alert.getEvidence(), equalTo(DEFAULT_ERROR_MESSAGE));

        // Test the lower-case error message
        msg =
                createHttpMessageWithRespBody(
                        "<html>" + DEFAULT_ERROR_MESSAGE.toLowerCase() + "</html>");

        scanHttpResponseReceive(msg);

        expectedAlerts++;
        assertThat(alertsRaised.size(), equalTo(expectedAlerts));
        alert = alertsRaised.get(expectedAlerts - 1);
        assertThat(alert.getCweId(), equalTo(200));
        assertThat(alert.getWascId(), equalTo(13));
        assertThat(alert.getEvidence(), equalTo(DEFAULT_ERROR_MESSAGE.toLowerCase()));

        // Test the upper-case error message
        msg =
                createHttpMessageWithRespBody(
                        "<html>" + DEFAULT_ERROR_MESSAGE.toUpperCase() + "</html>");

        scanHttpResponseReceive(msg);

        expectedAlerts++;
        assertThat(alertsRaised.size(), equalTo(expectedAlerts));
        alert = alertsRaised.get(expectedAlerts - 1);
        assertThat(alert.getCweId(), equalTo(200));
        assertThat(alert.getWascId(), equalTo(13));
        assertThat(alert.getEvidence(), equalTo(DEFAULT_ERROR_MESSAGE.toUpperCase()));
    }

    @Test
    public void passesIfNoDebugErrorsDisclosed() throws HttpMalformedHeaderException {
        String[] data =
                new String[] {
                    "Error Management theory",
                    "a subject can make two possible errors",
                    "What to Do If You Get a 404",
                    "500"
                };

        for (int i = 0; i < data.length; i++) {
            String debugError = data[i];

            HttpMessage msg = createHttpMessageWithRespBody("<html>" + debugError + "</html>");

            scanHttpResponseReceive(msg);

            assertThat(alertsRaised.size(), equalTo(0));
        }
    }

    @Test
    public void passesIfResponseIsEmpty() throws HttpMalformedHeaderException {
        HttpMessage msg = createHttpMessageWithRespBody("");

        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void passesIfResponseIsNotText() throws HttpMalformedHeaderException {
        HttpMessage msg = createHttpMessageWithRespBody(DEFAULT_ERROR_MESSAGE);
        msg.getResponseHeader()
                .setHeader(
                        HttpResponseHeader.CONTENT_TYPE,
                        "application/octet-stream;charset=ISO-8859-1");

        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotAlertIfJSResponseContainsErrorStringAtHighThreshold()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createHttpMessageWithRespBody(DEFAULT_ERROR_MESSAGE);
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "application/javascript");
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotAlertIfJSResponseContainsErrorStringAtMediumThreshold()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createHttpMessageWithRespBody(DEFAULT_ERROR_MESSAGE);
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "application/javascript");
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldAlertIfJSResponseContainsErrorStringAtLowThreshold()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createHttpMessageWithRespBody(DEFAULT_ERROR_MESSAGE);
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.CONTENT_TYPE, "application/javascript");
        // When
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(200));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(13));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(DEFAULT_ERROR_MESSAGE));
    }

    @Test
    public void changeDebugErrorsFile() throws HttpMalformedHeaderException {
        int expectedAlerts = 0;
        List<String> alternativeDebugErrors =
                Arrays.asList(
                        "Alternative Error", "This should also be dected as debug error message");

        // Should raise alert with default error messages loaded
        HttpMessage msg =
                createHttpMessageWithRespBody("<html>" + DEFAULT_ERROR_MESSAGE + "</html>");

        scanHttpResponseReceive(msg);

        expectedAlerts++;
        assertThat(alertsRaised.size(), equalTo(expectedAlerts));
        Alert alert = alertsRaised.get(expectedAlerts - 1);
        assertThat(alert.getCweId(), equalTo(200));
        assertThat(alert.getWascId(), equalTo(13));
        assertThat(alert.getEvidence(), equalTo(DEFAULT_ERROR_MESSAGE));

        // Should not raise alerts on alternative error definition yet
        for (int i = 0; i < alternativeDebugErrors.size(); i++) {
            String debugError = alternativeDebugErrors.get(i);
            msg = createHttpMessageWithRespBody("<html>" + debugError + "</html>");

            scanHttpResponseReceive(msg);

            assertThat(alertsRaised.size(), equalTo(expectedAlerts));
        }

        // Change debug error definitions for the scanner
        try {
            Path errorFile = testFolder.resolve("alternative-debug-error-messages.txt");
            Files.write(errorFile, alternativeDebugErrors, Charset.forName("UTF-8"));
            rule.setDebugErrorFile(errorFile);
        } catch (IOException e) {
            throw new RuntimeException("Could not write alternative debug error messages file.", e);
        }

        // Should NOT raise alert with default error messages loaded after changed definitions
        msg = createHttpMessageWithRespBody("<html>" + DEFAULT_ERROR_MESSAGE + "</html>");

        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(expectedAlerts));

        // Should raise alerts on alternative error definition now
        for (int i = 0; i < alternativeDebugErrors.size(); i++) {
            String debugError = alternativeDebugErrors.get(i);
            msg = createHttpMessageWithRespBody("<html>" + debugError + "</html>");

            scanHttpResponseReceive(msg);

            expectedAlerts++;
            assertThat(alertsRaised.size(), equalTo(expectedAlerts));
            alert = alertsRaised.get(expectedAlerts - 1);
            assertThat(alert.getCweId(), equalTo(200));
            assertThat(alert.getWascId(), equalTo(13));
            assertThat(alert.getEvidence(), equalTo(debugError));
        }
    }
}
