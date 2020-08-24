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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

public class JsoScanRuleUnitTest extends PassiveScannerTest<JsoScanRule> {

    /* Testing JSO in response */
    @Test
    public void shouldNotRaiseAlertGivenNoJsoHasBeenDetectedInResponse() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "X-Custom-Info: NOPE\r\n" + "Set-Cookie: NOPE=NOPE");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInHeaderOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Custom-Info: " + jso + "\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInCookieOfResponse()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: CRUNCHY=" + jso + "\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenRawJsoMagicBytesAreDetectedInRawBodyOfResponse()
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
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInBodyOfResponse()
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
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    /* Testing JSO in request */
    @Test
    public void shouldNotRaiseAlertGivenNoJsoHasBeenDetectedInRequest() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\n" + "X-Custom-Info: NOPE\r\n" + "Cookie: NOPE=NOPE\r\n");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInRequestParameterOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /some_action?q=" + createUriEncodedJso() + "&p=&m HTTP/1.1");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInRequestParameterOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET /some_action?q=" + jso + "&p=&m HTTP/1.1");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInHeaderOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-Custom-Info: " + createUriEncodedJso());

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInHeaderOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "X-Custom-Info: " + jso + "\r\n");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenUriEncodedJsoMagicBytesAreDetectedInCookieOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET / HTTP/1.1\r\n" + "Cookie: CRUNCHY=" + createUriEncodedJso() + "\r\n");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInCookieOfRequest()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1\r\n" + "Cookie: CRUNCHY=" + jso + "\r\n");

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenRawJsoMagicBytesAreDetectedInBodyOfRequest() throws Exception {
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
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenBase64JsoMagicBytesAreDetectedInBodyOfRequest()
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
        msg.setRequestBody(jso);

        // When
        scanHttpRequestSend(msg);

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

    private static String createUriEncodedJso() throws IOException {
        return URLEncoder.encode(
                new String(createJso(), StandardCharsets.ISO_8859_1),
                StandardCharsets.UTF_8.name());
    }

    @Override
    protected JsoScanRule createScanner() {
        return new JsoScanRule();
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
