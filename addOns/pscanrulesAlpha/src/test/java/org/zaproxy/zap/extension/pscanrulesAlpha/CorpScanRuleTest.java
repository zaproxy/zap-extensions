/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

class CorpScanRuleTest extends PassiveScannerTest<CorpScanRule> {

    @Test
    public void shouldRaiseCorpAlertWhenResponseDoesntSendCorpHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(CorpScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void shouldRaiseCorpAlertWhenCorpHeaderIsSetForSameSite() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nCross-Origin-Resource-Policy: same-site\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(CorpScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same-site"));
    }

    @Test
    public void shouldRaiseCorpAlertWhenCorpHeaderContentIsUnexpected() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nCross-Origin-Resource-Policy: unexpected\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(CorpScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("unexpected"));
    }

    @Test
    public void shouldRaiseCorpAlertCaseInsensitive() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nCross-Origin-Resource-Policy: same-SITE\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(CorpScanRule.CROSS_ORIGIN_RESOURCE_POLICY_HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same-SITE"));
    }

    @Test
    public void shouldNotRaiseCorpAlertWhenCorpHeaderIsSetForSameOrigin() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nCross-Origin-Resource-Policy: same-origin\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotRaiseCorpAlertWhenCorpHeaderIsSetForCrossOrigin() throws Exception {
        // We consider that resource has been explicitly set to be shared.
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nCross-Origin-Resource-Policy: cross-origin\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldRaiseCorpAlertOnlyForSuccessfulQueries() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET / HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 500 Internal Server Error\r\n");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Override
    protected CorpScanRule createScanner() {
        return new CorpScanRule();
    }
}
