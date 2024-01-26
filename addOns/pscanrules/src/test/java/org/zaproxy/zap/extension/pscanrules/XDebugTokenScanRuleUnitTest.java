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
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class XDebugTokenScanRuleUnitTest extends PassiveScannerTest<XDebugTokenScanRule> {

    private static final String X_DEBUG_TOKEN_HEADER = "X-Debug-Token";
    private static final String X_DEBUG_TOKEN_LINK_HEADER = "X-Debug-Token-Link";

    @Override
    protected XDebugTokenScanRule createScanner() {
        return new XDebugTokenScanRule();
    }

    private HttpMessage createMessage() throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");

        return msg;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(200)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ERRH_01_ERR.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // THen
        assertThat(alerts.size(), is(equalTo(1)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    @Test
    void shouldNotRaiseAlertIfThereIsNoRelevantHeader() throws Exception {
        // Given
        HttpMessage msg = createMessage();

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAnAlertIfFindsXDebugToken() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setHeader(X_DEBUG_TOKEN_HEADER, "9687e6");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("X-Debug-Token: 9687e6"));
    }

    @Test
    void shouldRaiseAnAlertIfFindsXDebugTokenLink() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().setHeader(X_DEBUG_TOKEN_LINK_HEADER, "/_profiler/97b958");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(alertsRaised.get(0).getEvidence(), is("X-Debug-Token-Link: /_profiler/97b958"));
    }

    @Test
    void shouldRaiseOnlyOneAlertIfBothHeaderVariantsFound() throws Exception {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader()
                .setHeader(X_DEBUG_TOKEN_LINK_HEADER, "https://www.example.com/_profiler/9687e6");
        msg.getResponseHeader().setHeader(X_DEBUG_TOKEN_HEADER, "9687e6");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                is("X-Debug-Token-Link: https://www.example.com/_profiler/9687e6"));
    }
}
