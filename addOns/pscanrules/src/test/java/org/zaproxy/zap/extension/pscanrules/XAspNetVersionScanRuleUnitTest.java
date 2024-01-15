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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class XAspNetVersionScanRuleUnitTest extends PassiveScannerTest<XAspNetVersionScanRule> {

    @Override
    protected XAspNetVersionScanRule createScanner() {
        return new XAspNetVersionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(933)));
        assertThat(wasc, is(equalTo(14)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(
                        CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INFO_08_FINGERPRINT_APP_FRAMEWORK.getValue())));
    }

    @Test
    void shouldRaiseAlertWhenResponseContainsXAspNetVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNet-Version");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    void shouldRaiseAlertWhenResponseContainsXAspNetMvcVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("X-AspNetMvc-Version");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("1/1.1"));
    }

    @Test
    void shouldNotRaiseAlertWhenResponseDoesNotContainsXAspNetVersionHeader()
            throws HttpMalformedHeaderException {

        HttpMessage msg = createMessage("dummy");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        String MESSAGE_PREFIX = "pscanrules.xaspnetversion.";

        List<Alert> alerts = rule.getExampleAlerts();

        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
        assertThat(
                alert.getReference(),
                equalTo(Constant.messages.getString(MESSAGE_PREFIX + "refs")));
        assertThat(alert.getEvidence(), equalTo("1/1.1"));
        assertThat(
                alert.getSolution(), equalTo(Constant.messages.getString(MESSAGE_PREFIX + "soln")));
        assertThat(
                alert.getDescription(),
                equalTo(Constant.messages.getString(MESSAGE_PREFIX + "desc")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
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
