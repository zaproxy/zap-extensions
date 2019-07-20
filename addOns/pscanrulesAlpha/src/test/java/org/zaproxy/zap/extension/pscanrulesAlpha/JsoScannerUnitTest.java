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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.*;
import java.util.*;
import org.junit.*;
import org.parosproxy.paros.network.*;

public class JsoScannerUnitTest extends PassiveScannerTest<JsoScanner> {
    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInHeader() throws Exception {
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Custom-Info: " + jso + "\r\n");

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInCookie() throws Exception {
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: CRUNCHY=" + jso + "\r\n");

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldNotRaiseAlertGivenNoJsoHasBeenDetected() throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "X-Custom-Info: NOPE\r\n");

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised, empty());
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInRawBody() throws Exception {
        HttpMessage msg = new HttpMessage();
        byte[] jso = createJso();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length
                        + "\r\n");
        msg.setResponseBody(jso);

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldRaiseAlertGivenJsoMagicBytesAreDetectedInBase64Body() throws Exception {
        HttpMessage msg = new HttpMessage();
        String jso = Base64.getEncoder().encodeToString(createJso());

        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "Content-Disposition: attachment; filename=\"jso.bin\"\r\n"
                        + "Content-Length: "
                        + jso.length()
                        + "\r\n");
        msg.setResponseBody(jso);

        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

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
