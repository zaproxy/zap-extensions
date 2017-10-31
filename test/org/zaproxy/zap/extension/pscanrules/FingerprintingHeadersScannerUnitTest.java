/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class FingerprintingHeadersScannerUnitTest extends PassiveScannerTest {

    @Override
    protected FingerprintingHeadersScanner createScanner() {
        return new FingerprintingHeadersScanner();
    }

    @Test
    public void hasServerHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "Server: Apache-Coyote/1.1\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("Headers"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Server:Apache-Coyote/1.1"));
    }

    @Test
    public void hasXPoweredByHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "X-Powered-By: Apache-Coyote/1.1\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("Headers"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-Powered-By:Apache-Coyote/1.1"));
    }

    @Test
    public void hasXAspNetVersionHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "X-AspNet-Version: 1\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("Headers"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-AspNet-Version:1"));
    }

    @Test
    public void hasXAspNetMvcVersionHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "X-AspNetMvc-Version: 1\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("Headers"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-AspNetMvc-Version:1"));
    }

    @Test
    public void noFingerprintingHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "X-XSS-Protection: \r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void alertThresholdLow() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        "Server: Apache-Coyote/1.1\r\n" +
                        "X-XSS-Protection: 0\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.setLevel(AlertThreshold.LOW);
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

}
