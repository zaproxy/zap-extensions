/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class XChromeLoggerDataInfoLeakScanRuleUnitTest
        extends PassiveScannerTest<XChromeLoggerDataInfoLeakScanRule> {

    private static final String XCLD = "X-ChromeLogger-Data";
    private static final String XCPD = "X-ChromePhp-Data";
    private static final String XCLD_VALUE =
            "eyJ2ZXJzaW9uIjoiNC4wIiwiY29sdW"
                    + "1ucyI6WyJsYWJlbCIsImxvZyIsImJhY2t0cmFjZSIsInR5cGUiXSwicm93cyI"
                    + "6W1sicmVxdWVzdCIsIk1hdGNoZWQgcm91dGUgXCJhcHBfc2VjdXJpdHlfbG9n"
                    + "aW5cIiAocGFyYW1ldGVyczogXCJfY29udHJvbGxlclwiOiBcIkJhY2tFbmRcX"
                    + "EFwcEJ1bmRsZVxcQ29udHJvbGxlclxcU2VjdXJpdHlDb250cm9sbGVyOjpsb2"
                    + "dpbkFjdGlvblwiLCBcIl9yb3V0ZVwiOiBcImFwcF9zZWN1cml0eV9sb2dpblw"
                    + "iKSIsInVua25vd24iLCJpbmZvIl0sWyJzZWN1cml0eSIsIlBvcHVsYXRlZCBT"
                    + "ZWN1cml0eUNvbnRleHQgd2l0aCBhbiBhbm9ueW1vdXMgVG9rZW4iLCJ1bmtub"
                    + "3duIiwiaW5mbyJdXSwicmVxdWVzdF91cmkiOiJcL2xvZ2luIn0=";

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected XChromeLoggerDataInfoLeakScanRule createScanner() {
        return new XChromeLoggerDataInfoLeakScanRule();
    }

    @Test
    void shouldNotRaiseAlertIfResponseHasNoRelevantHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseBody("Some text <h1>Some Title Element</h1>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertIfResponseHasRelevantHeader() throws IOException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(XCLD, XCLD_VALUE);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(XCLD_VALUE));
        String otherInfo =
                "The following represents an attempt to base64 decode the value:\n"
                        + new String(
                                Base64.getDecoder().decode(XCLD_VALUE), StandardCharsets.UTF_8);
        assertThat(alertsRaised.get(0).getOtherInfo(), equalTo(otherInfo));
    }

    @Test
    void shouldRaiseAlertIfResponseHasAlternateRelevantHeader() throws IOException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(XCPD, XCLD_VALUE);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(XCLD_VALUE));
        String otherInfo =
                "The following represents an attempt to base64 decode the value:\n"
                        + new String(
                                Base64.getDecoder().decode(XCLD_VALUE), StandardCharsets.UTF_8);
        assertThat(alertsRaised.get(0).getOtherInfo(), equalTo(otherInfo));
    }

    @Test
    void shouldRaiseAlertIfResponseHasAlternateRelevantHeaderEvenWithInvalidEncoding()
            throws IOException {
        // Given
        HttpMessage msg = createMessage();
        String malformedEncodedValue = "ê" + XCLD_VALUE;
        msg.getResponseHeader().addHeader(XCPD, malformedEncodedValue);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(malformedEncodedValue));
        String otherInfo = "Header value could not be base64 decoded: " + malformedEncodedValue;
        assertThat(alertsRaised.get(0).getOtherInfo(), equalTo(otherInfo));
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
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();

        // Then
        assertThat(alerts.size(), is(equalTo(1)));

        Alert alert = alerts.get(0);
        Map<String, String> tags1 = alert.getTags();
        assertThat(tags1.size(), is(equalTo(4)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_HIGH)));
        assertThat(tags1, hasKey("CWE-200"));
        assertThat(
                tags1.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags1.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }
}
