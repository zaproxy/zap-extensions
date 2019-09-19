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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class SubResourceIntegrityAttributeScannerTest
        extends PassiveScannerTest<SubResourceIntegrityAttributeScanner> {

    @Override
    protected SubResourceIntegrityAttributeScanner createScanner() {
        SubResourceIntegrityAttributeScanner scanner = new SubResourceIntegrityAttributeScanner();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    public void shouldNotRaiseAlertGivenIntegrityAttributeIsPresentInLinkElement()
            throws HttpMalformedHeaderException {
        // Given
        // From https://www.w3.org/TR/SRI/#use-casesexamples
        HttpMessage msg =
                buildMessage(
                        "<html><head><link href=\"https://site53.example.net/style.css\"\n"
                                + "      integrity=\"sha384-+/M6kredJcxdsqkczBUjMLvqyHb1K/JThDXWsBVxMEeZHEaMKEOEct339VItX1zB\"\n"
                                + "      ></head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertGivenIntegrityAttributeIsPresentInScriptElement()
            throws HttpMalformedHeaderException {
        // Given
        // From https://www.w3.org/TR/SRI/#use-casesexamples
        HttpMessage msg =
                buildMessage(
                        "<html><head><script src=\"https://analytics-r-us.example.com/v1.0/include.js\"\n"
                                + "        integrity=\"sha384-MBO5IDfYaE6c6Aao94oZrIOiC6CGiSN2n4QUbHNPhzk5Xhm0djZLQqTpL0HzTUxk\"\n"
                                + "        ></script></head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertGivenIntegrityAttributeIsMissingForSupportedElement()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.get(0).getPluginId(), equalTo(rule.getPluginId()));
    }

    @Test
    public void shouldIndicateElementWithoutIntegrityAttribute()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"));
    }

    @Test
    public void shouldNotRaiseAlertGivenElementIsServedByCurrentDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://example.com/v1.0/include.js\"></script>"
                                + "<link href=\"http://example.com/v1.0/style.css\"></script>"
                                + "</head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertGivenElementIsServedBySubDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://subdomain.example.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    public void shouldIgnoreInvalidFormattedHostname() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://in(){}\\#~&/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    private static HttpMessage buildMessage(String body) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://example.com/ HTTP/1.1");
        msg.setResponseBody(body);
        return msg;
    }
}
