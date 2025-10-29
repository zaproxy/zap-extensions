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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;

class CharsetMismatchScanRuleUnitTest extends PassiveScannerTest<CharsetMismatchScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.charsetmismatch.";
    private static final String HEADER_METACONTENTYPE_MISMATCH =
            BASE_RESOURCE_KEY + "name.header_metacontentype_mismatch";
    private static final String HEADER_METACHARSET_MISMATCH =
            BASE_RESOURCE_KEY + "name.header_metacharset_mismatch";
    private static final String METACONTENTTYPE_METACHARSET_MISMATCH =
            BASE_RESOURCE_KEY + "name.metacontenttype_metacharset_mismatch";
    private static final String XML_MISMATCH = BASE_RESOURCE_KEY + "extrainfo.xml";

    private static final String HEADER_WITH_CL_PLACEHOLDER =
            """
            HTTP/1.1 200 OK\r
            Server: Apache-Coyote/1.1\r
            Content-Type: text/html;charset=UTF-8\r"
            Content-Length: %s\r""";
    private HttpMessage msg;

    @BeforeEach
    void before() throws HttpMalformedHeaderException {
        rule.setAlertThreshold(AlertThreshold.LOW);

        msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
    }

    @Override
    protected CharsetMismatchScanRule createScanner() {
        return new CharsetMismatchScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(4)));
        long countInfos =
                alerts.stream().filter(alert -> Alert.RISK_INFO == alert.getRisk()).count();
        assertThat(countInfos, is(equalTo(4L)));
    }

    @Test
    void shouldPassWhenZeroContentLength() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(0));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"text/html"})
    void shouldPassWhenNoHeaderCharset(String type) throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, type);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldPassWhenTheSameMetaCharsetAndHeaderHtml() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=UTF-8' />"
                        + "<meta charset='UTF-8' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertWhenDifferentMetaCharsetAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>" + "<head>" + "<meta charset='ISO-123' />" + "</head>" + "</html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }

    @Test
    void shouldRaiseAlertWhenDifferentBodyCharsetAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=ISO-123' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACONTENTYPE_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }

    @Test
    void shouldRaiseAlertWhenDifferentMetaAndHeaderPlusAdditionalMetaParametersHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta charset='ISO-123' />"
                        + "<meta name='CUSTOM_NAME' content='CUSTOM_VALUE'/>"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }

    @Test
    void shouldRaiseAlertWhenDifferentMetaCharsetAndContentType()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=UTF-8' />"
                        + "<meta charset='ISO-123' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(
                alertsRaised.get(0),
                containsNameLoadedWithKey(METACONTENTTYPE_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));

        assertThat(alertsRaised.get(1), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(1).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(1).getWascId(), equalTo(15));
    }

    @Test
    void shouldPassWhenTheSameEncodingAndHeaderXml() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<?xml version='1.0' encoding='UTF-8'?>" + "<zap></zap>");
        msg.setResponseHeader(HEADER_WITH_CL_PLACEHOLDER.formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertWhenDifferentEncodingAndHeaderXml() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<?xml version='1.0' encoding='ISO-123'?>" + "<zap></zap>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0),
                containsOtherInfoLoadedWithKey(XML_MISMATCH, "UTF-8", "ISO-123"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(436));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }
}
