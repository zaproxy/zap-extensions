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

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class InsecureJsfViewStatePassiveScanRuleUnitTest
        extends PassiveScannerTest<InsecureJsfViewStatePassiveScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.insecurejsfviewstate.";
    private static final String INSECURE_JSF = BASE_RESOURCE_KEY + "name";

    @Override
    protected InsecureJsfViewStatePassiveScanRule createScanner() {
        return new InsecureJsfViewStatePassiveScanRule();
    }

    @Test
    public void shouldPassAsThereIsNoBody() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody("");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassWhenViewStateContainsUnderscore() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='_id1231'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassNoJavaWordInViewState() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        String encoded = Base64.encodeBytes("secureValue".getBytes(), Base64.GZIP);
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='"
                        + encoded
                        + "'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassIfViewStateIsStoredOnServer() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        // server side contains :, clear text no base64 or encryption
        String serverSideViewState = "123:123";
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='"
                        + serverSideViewState
                        + "'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfViewStateContainsJavaWord() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        String encoded = Base64.encodeBytes("insecureValue_java".getBytes(), Base64.DONT_GUNZIP);
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='"
                        + encoded
                        + "'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(INSECURE_JSF));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
    }

    @Test
    public void shouldRaiseAlertIfViewStateContainsJavaWordCompressed() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        String encoded = Base64.encodeBytes("insecureValue_java".getBytes(), Base64.GZIP);
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='"
                        + encoded
                        + "'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(INSECURE_JSF));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
    }

    @Test
    public void shouldRaiseAlertIfInsecureValueViewStateIdWithFormId() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        String encoded = Base64.encodeBytes("insecureValue_java".getBytes(), Base64.GZIP);
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='hidden' id='j_id1:javax.faces.ViewState:0' value='"
                        + encoded
                        + "'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(INSECURE_JSF));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
    }

    @Test
    public void shouldRaiseAlertIfInsecureViewStateManyInputs() throws IOException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        String encoded = Base64.encodeBytes("insecureValue_java".getBytes(), Base64.GZIP);
        msg.setResponseBody(
                "<html><head></head>"
                        + "<body>"
                        + "<input type='text' id='input1' value='input1'/>"
                        + "<input type='text' id='input2' value='input2'/>"
                        + "<input type='hidden' id='input3' value='input3'/>"
                        + "<input type='hidden' id='javax.faces.viewstate' value='"
                        + encoded
                        + "'/>"
                        + "<input type='hidden' id='input4' value='input4'/>"
                        + "</body>"
                        + "</html>");
        setTextHtmlResponseHeader(msg);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(INSECURE_JSF));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(14));
    }

    private void setTextHtmlResponseHeader(HttpMessage msg) throws HttpMalformedHeaderException {
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n");
    }
}
