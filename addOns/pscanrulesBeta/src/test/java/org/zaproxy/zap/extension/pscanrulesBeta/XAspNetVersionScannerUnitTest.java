/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class XAspNetVersionScannerUnitTest extends PassiveScannerTest<XAspNetVersionScanner> {

    @Override
    protected XAspNetVersionScanner createScanner() {
        return new XAspNetVersionScanner();
    }


    @Test
    public void shouldRaiseAlertWhenResponseContainsXAspNetVersionHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNet-Version");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsXAspNetMvcVersionHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNetMvc-Version");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    public void shouldNotRaiseAlertWhenResponseDoesNotContainsXAspNetVersionHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("dummy");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    private HttpMessage createMessage(String header) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                        header + ": 1/1.1\r\n" +
                        "X-XSS-Protection: 0\r\n" +
                        "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                        "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        return msg;
    }

}
