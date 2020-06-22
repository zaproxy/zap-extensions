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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class CharsetMismatchScanRuleUnitTest extends PassiveScannerTest<CharsetMismatchScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.charsetmismatch.";
    private static final String NO_MISMATCH_METACONTENTTYPE_MISSING =
            BASE_RESOURCE_KEY + "variant.no_mismatch_metacontenttype_missing";
    private static final String HEADER_METACONTENTYPE_MISMATCH =
            BASE_RESOURCE_KEY + "variant.header_metacontentype_mismatch";
    private static final String HEADER_METACHARSET_MISMATCH =
            BASE_RESOURCE_KEY + "variant.header_metacharset_mismatch";
    private static final String METACONTENTTYPE_METACHARSET_MISMATCH =
            BASE_RESOURCE_KEY + "variant.metacontenttype_metacharset_mismatch";
    private static final String XML_MISMATCH = BASE_RESOURCE_KEY + "extrainfo.xml";

    private HttpMessage msg;

    @BeforeEach
    public void before() throws HttpMalformedHeaderException {
        rule.setAlertThreshold(AlertThreshold.LOW);

        msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
    }

    @Override
    protected CharsetMismatchScanRule createScanner() {
        return new CharsetMismatchScanRule();
    }

    @Test
    public void shouldPassWhenZeroContentLength() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: 0\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassWhenNoHeaderCharset() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassWhenNoContentType() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldPassWhenTheSameMetaCharsetAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=UTF-8' />"
                        + "<meta charset='UTF-8' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertWhenDifferentMetaCharsetAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>" + "<head>" + "<meta charset='ISO-123' />" + "</head>" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));

        assertThat(
                alertsRaised.get(1),
                containsNameLoadedWithKey(NO_MISMATCH_METACONTENTTYPE_MISSING));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(1).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(1).getWascId(), equalTo(15));
    }

    @Test
    public void shouldRaiseAlertWhenNoBodyCharsetTheSameMetaAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>" + "<head>" + "<meta charset='UTF-8' />" + "</head>" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0),
                containsNameLoadedWithKey(NO_MISMATCH_METACONTENTTYPE_MISSING));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }

    @Test
    public void shouldRaiseAlertWhenDifferentBodyCharsetAndHeaderHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=ISO-123' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACONTENTYPE_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }

    @Test
    public void shouldRaiseAlertWhenDifferentMetaAndHeaderPlusAdditionalMetaParametersHtml()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta charset='ISO-123' />"
                        + "<meta name='CUSTOM_NAME' content='CUSTOM_VALUE'/>"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));

        assertThat(
                alertsRaised.get(1),
                containsNameLoadedWithKey(NO_MISMATCH_METACONTENTTYPE_MISSING));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(1).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(1).getWascId(), equalTo(15));
    }

    @Test
    public void shouldRaiseAlertWhenDifferentMetaCharsetAndContentType()
            throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<meta http-equiv='Content-Type' content='charset=UTF-8' />"
                        + "<meta charset='ISO-123' />"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=UTF-8\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(
                alertsRaised.get(0),
                containsNameLoadedWithKey(METACONTENTTYPE_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));

        assertThat(alertsRaised.get(1), containsNameLoadedWithKey(HEADER_METACHARSET_MISMATCH));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
        assertThat(alertsRaised.get(1).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(1).getWascId(), equalTo(15));
    }

    @Test
    public void shouldPassWhenTheSameEncodingAndHeaderXml() throws HttpMalformedHeaderException {
        // Given
        msg.setResponseBody("<?xml version='1.0' encoding='UTF-8'?>" + "<zap></zap>");
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
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertWhenDifferentEncodingAndHeaderXml()
            throws HttpMalformedHeaderException {
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
        assertThat(alertsRaised.get(0).getCweId(), equalTo(16));
        assertThat(alertsRaised.get(0).getWascId(), equalTo(15));
    }
}
