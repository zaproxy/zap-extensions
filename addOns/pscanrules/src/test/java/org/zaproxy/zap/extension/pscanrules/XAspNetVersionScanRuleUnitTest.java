/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class XAspNetVersionScanRuleUnitTest extends PassiveScannerTest<XAspNetVersionScanRule> {

    @Override
    protected XAspNetVersionScanRule createScanner() {
        return new XAspNetVersionScanRule();
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsXAspNetVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNet-Version");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsXAspNetMvcVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNetMvc-Version");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    public void shouldNotRaiseAlertWhenResponseDoesNotContainsXAspNetVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("dummy");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    private HttpMessage createMessage(String header) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + header
                        + ": 1/1.1\r\n"
                        + "X-XSS-Protection: 0\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        return msg;
    }
}
