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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

/** @author Vahid Rafiei (@vahid_r) */
public class XPoweredByHeaderInfoLeakScanRuleUnitTest
        extends PassiveScannerTest<XPoweredByHeaderInfoLeakScanRule> {

    @Override
    protected XPoweredByHeaderInfoLeakScanRule createScanner() {
        return new XPoweredByHeaderInfoLeakScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfThereIsNoXPoweredBy() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldRaiseAnAlertIfFindsXPoweredBy() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Powered-By: Servlet/3.0\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("X-Powered-By: Servlet/3.0"));
    }

    @Test
    public void shouldRaiseOnlyOneAlertWithOneEvidenceAndOtherInfoIfFindsMultipleXPoweredBy()
            throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Powered-By: PHP/5.4\r\n"
                        + "X-Powered-By: Servlet/3.0\r\n"
                        + "X-Powered-By: ASP.NET\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("X-Powered-By: PHP/5.4"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("X-Powered-By: Servlet/3.0"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("X-Powered-By: ASP.NET"));
    }

    @Test
    public void shouldBeCaseSensitiveWhenShowingHeadersInEvidenceAndOtherInfo() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Powered-By: PHP/5.4\r\n"
                        + "x-pOwEReD-bY: Servlet/3.0\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("X-Powered-By: PHP/5.4"));
        assertThat(alertsRaised.get(0).getOtherInfo(), containsString("x-pOwEReD-bY: Servlet/3.0"));
    }
}
