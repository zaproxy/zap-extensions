/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

class GetForPostScanRuleUnitTest extends ActiveScannerTest<GetForPostScanRule> {

    @Override
    protected GetForPostScanRule createScanner() {
        return new GetForPostScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(16)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_06_HTTP_METHODS.getValue())));
    }

    @Test
    void shouldRaiseAlertIfGetAndPostResponsesAreSameWithDifferentTimeInBody()
            throws HttpMalformedHeaderException {
        // Given
        String testPath = "/shouldRaiseAlertIfGetAndPostResponsesAreSameWithDifferentTimeInBody/";
        this.nano.addHandler(
                new NanoServerHandler(testPath) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(getResponseForPostRequest("1:30"));
                    }
                });
        HttpMessage msg = createMsg(testPath, getResponseForPostRequest("12:00"));
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    void shouldNotRaiseAlertIfResponsesAreDifferentForGetAndPost()
            throws HttpMalformedHeaderException {
        // Given
        String testPath = "/shouldNotRaiseAlertIfResponsesAreDifferentForGetAndPost/";
        this.nano.addHandler(
                new NanoServerHandler(testPath) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(getResponseForGetRequest());
                    }
                });
        HttpMessage msg = createMsg(testPath, getResponseForPostRequest("12:00"));
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given /  When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(alert.getEvidence(), is(equalTo("HTTP/1.0 200")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private HttpMessage createMsg(String testPath, String response)
            throws HttpMalformedHeaderException {
        HttpMessage msg = this.getHttpMessage("POST", "text/html", testPath, response);
        TreeSet<HtmlParameter> treeSet = new TreeSet<>();
        treeSet.add(new HtmlParameter(HtmlParameter.Type.form, "key", "value"));
        msg.setFormParams(treeSet);
        msg.getRequestHeader()
                .setHeader(HttpFieldsNames.CONTENT_TYPE, "application/x-www-form-urlencoded");
        return msg;
    }

    private static String getResponseForPostRequest(String time) {
        return "<html>"
                + "<body>"
                + "This is a response for post request. Time is "
                + time
                + "</body>"
                + "</html>";
    }

    private static String getResponseForGetRequest() {
        return "<html>"
                + "<body>"
                + "Get request is not allowed for this method"
                + "</body>"
                + "</html>";
    }
}
