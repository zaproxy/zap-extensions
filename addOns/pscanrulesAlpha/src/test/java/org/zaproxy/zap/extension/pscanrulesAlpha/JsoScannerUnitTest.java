/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;
import org.junit.Ignore;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;

public class JsoScannerUnitTest extends PassiveScannerTest<JsoScanner> {

    public static final String URI_ENCODED_JSO =
            "%C2%AC%C3%AD%00%05sr%00Eorg.zaproxy.zap.extension.pscanrulesAlpha.JsoScannerUnitTest%24AnObject%00%00%00%00%00%00%00%01%02%00%00xp";

    @Test
    public void shouldNotRaiseAlertGivenNoJsoHasBeenDetected() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Custom-Info: NOPE\r\n");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInHeaderOfResponse() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Custom-Info: " + jso + "\r\n");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInCookieOfResponse() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: CRUNCHY=" + jso + "\r\n");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInRawBodyOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        byte[] jso = createJso();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length
                        + "\r\n");
        msg.setResponseBody(jso);

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInBase64BodyOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length()
                        + "\r\n");
        msg.setResponseBody(jso);

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInRequestParameterOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /some_action?q=" + URI_ENCODED_JSO + "&p=&m HTTP/1.1");

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInRequestParameterOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET /some_action?q=" + jso + "&p=&m HTTP/1.1");

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInHeaderOfRequest() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-Custom-Info: " + jso + "\r\n");

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInCookieOfRequest() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Cookie: CRUNCHY=" + jso + "\r\n");

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInRawBodyOfPOSTRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        byte[] jso = createJso();
        msg.setRequestHeader(
                "POST / HTTP/1.1\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length
                        + "\r\n");
        msg.setRequestBody(jso);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Ignore
    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInBase64BodyOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length()
                        + "\r\n");
        msg.setResponseBody(jso);

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Ignore
    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInRequestParameterOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /some_action?q=" + URI_ENCODED_JSO + "&p= HTTP/1.1");

        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInHeaderOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-Custom-Info: " + URI_ENCODED_JSO);

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInCookieOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Cookie: CRUNCHY=" + URI_ENCODED_JSO + "\r\n");

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    private static byte[] createJso() throws IOException {
        AnObject anObject = new AnObject();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(out);
        objectOutputStream.writeObject(anObject);
        return out.toByteArray();
    }

    @Override
    protected JsoScanner createScanner() {
        return new JsoScanner();
    }

    private static class AnObject implements Serializable {
        private static final long serialVersionUID = 1L;
        private static String value;

        public static String getValue() {
            return value;
        }

        public static void setValue(String value) {
            AnObject.value = value;
        }
    }
}
