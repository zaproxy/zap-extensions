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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class BigRedirectsScanRuleUnitTest extends PassiveScannerTest<BigRedirectsScanRule> {
    private static final String URI = "http://example.com";
    private static final int ALLOWABLE_BODY_SIZE = URI.length() + 300;

    private HttpMessage msg;

    @BeforeEach
    void createHttpMessage() throws IOException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI(URI, false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Override
    protected BigRedirectsScanRule createScanner() {
        return new BigRedirectsScanRule();
    }

    @Test
    void givenRedirectWithSmallBodyThenItRaisesNoAlert() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenRedirectHeadersWithLargeBodyThenAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertBigAlertAttributes(alertsRaised.get(0));
    }

    @Test
    void givenRedirectHeadersWithSmallBodyButMultipleHrefsThenAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(
                "<html><a href=\""
                        + URI.toString()
                        + "\">Home</a>"
                        + "<br>"
                        + "<a href=\""
                        + URI.toString()
                        + "/admin\">Admin</a>"
                        + "</html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(1));
        assertMultiAlertAttributes(alertsRaised.get(0), "2");
    }

    @Test
    void givenNotModifiedStatusCodeWithLargeBodyThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_MODIFIED);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenNotFoundStatusCodeWithLargeBodyThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_FOUND);
        msg.getResponseHeader().setHeader(HttpHeader.LOCATION, URI);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void givenRedirectStatusCodeWithoutLocationHeaderThenNoAlertRaised() {
        // Given
        msg.getResponseHeader().setStatusCode(HttpStatusCode.MOVED_PERMANENTLY);
        msg.setResponseBody(new byte[ALLOWABLE_BODY_SIZE + 1]);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INFO_05_CONTENT_LEAK.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(2)));
        assertBigAlertAttributes(alerts.get(0));
        assertMultiAlertAttributes(alerts.get(1), "3");
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private static void assertBigAlertAttributes(Alert alert) {
        assertThat(alert.getRisk(), is(Alert.RISK_LOW));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getName(), is(getLocalisedString("name")));
        assertThat(alert.getDescription(), is(getLocalisedString("desc")));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getOtherInfo(), is(getExpectedBigExtraInfo()));
        assertThat(alert.getCweId(), is(201));
        assertThat(alert.getWascId(), is(13));
        assertThat(alert.getAlertRef(), is("10044-1"));
    }

    private static String getExpectedBigExtraInfo() {
        return getLocalisedString(
                "extrainfo", URI.length(), URI, ALLOWABLE_BODY_SIZE, ALLOWABLE_BODY_SIZE + 1);
    }

    private static void assertMultiAlertAttributes(Alert alert, String count) {
        assertThat(alert.getRisk(), is(Alert.RISK_LOW));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getName(), is(getLocalisedString("multi.name")));
        assertThat(alert.getDescription(), is(getLocalisedString("multi.desc")));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getOtherInfo(), is(getExpectedMultiExtraInfo(count)));
        assertThat(alert.getCweId(), is(201));
        assertThat(alert.getWascId(), is(13));
        assertThat(alert.getAlertRef(), is("10044-2"));
    }

    private static String getExpectedMultiExtraInfo(String count) {
        return getLocalisedString("multi.extrainfo", count);
    }

    private static String getLocalisedString(String key, Object... params) {
        return Constant.messages.getString("pscanrules.bigredirects." + key, params);
    }
}
