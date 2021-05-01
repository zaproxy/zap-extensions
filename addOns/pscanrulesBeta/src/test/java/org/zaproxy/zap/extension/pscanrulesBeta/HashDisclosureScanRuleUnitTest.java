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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link HashDisclosureScanRule}. */
public class HashDisclosureScanRuleUnitTest extends PassiveScannerTest<HashDisclosureScanRule> {

    @Override
    protected HashDisclosureScanRule createScanner() {
        return new HashDisclosureScanRule();
    }

    @BeforeEach
    public void before() throws HttpMalformedHeaderException {
        rule.setAlertThreshold(AlertThreshold.LOW); // Required by MD4/MD5 tests
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsUpperMd5Hash() throws Exception {
        // Given - Upper MD5
        String hashVal = "DD6433D07B73FC14A2A4D03C5A8FAA90";
        HttpMessage msg = createMsg(hashVal);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), is("Hash Disclosure - MD4 / MD5"));
        assertThat(alertsRaised.get(0).getEvidence(), is(hashVal));
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsLowerMd5Hash() throws Exception {
        // Given - Lower MD5
        String hashVal = "cc03e747a6afbbcbf8be7668acfebee5";
        HttpMessage msg = createMsg(hashVal);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), is("Hash Disclosure - MD4 / MD5"));
        assertThat(alertsRaised.get(0).getEvidence(), is(hashVal));
    }

    @Test
    public void shouldRaiseAlertWhenResponseContainsCookieWithMd5Hash() throws Exception {
        // Given - Lower MD5
        String hashVal = "cc03e747a6afbbcbf8be7668acfebee5";
        HttpMessage msg = createMsg("");
        msg.getResponseHeader().addHeader(HttpHeader.SET_COOKIE, "userid=" + hashVal);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getName(), is("Hash Disclosure - MD4 / MD5"));
        assertThat(alertsRaised.get(0).getEvidence(), is(hashVal));
    }

    @Test
    public void shouldNotRaiseAlertWhenResponseContainsNonMd5Hash() throws Exception {
        // Given - Not MD5 (mm)
        String hashVal = "mm6433d07b73fc14a2a4d03c5a8faa90";
        HttpMessage msg = createMsg(hashVal);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void shouldNotRaiseAlertWhenResponseContainsObviousJsessionid() throws Exception {
        // Given - jsessionid cookie
        String hashVal = "dd6433d07b73fc14a2a4d03c5a8faa90";
        HttpMessage msg = createMsg("");
        msg.getResponseHeader().addHeader(HttpHeader.SET_COOKIE, "jsessionid=" + hashVal);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    private HttpMessage createMsg(String hashVal) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");
        msg.setResponseBody("{\"hash\": \"" + hashVal + "\"}");
        return msg;
    }
}
