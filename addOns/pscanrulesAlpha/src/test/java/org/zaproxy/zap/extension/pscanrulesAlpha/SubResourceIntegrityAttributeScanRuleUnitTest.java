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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class SubResourceIntegrityAttributeScanRuleUnitTest
        extends PassiveScannerTest<SubResourceIntegrityAttributeScanRule> {

    @Override
    protected SubResourceIntegrityAttributeScanRule createScanner() {
        SubResourceIntegrityAttributeScanRule rule = new SubResourceIntegrityAttributeScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        return rule;
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
        scanHttpResponseReceive(msg);

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
        scanHttpResponseReceive(msg);

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
        scanHttpResponseReceive(msg);

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
        scanHttpResponseReceive(msg);

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
        scanHttpResponseReceive(msg);

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
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    public void shouldNotRaiseAlertGivenElementIsServedRelatively()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<!doctype html>\n"
                                + "<html lang=\"en\">\n"
                                + "  <head>\n"
                                + "    <link href=\"/dashboard/stylesheets/normalize.css\" rel=\"stylesheet\" type=\"text/css\" />\n"
                                + "  </head>\n"
                                + "  <body class=\"index\">\n"
                                + "  </body>\n"
                                + "</html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertGivenElementIsInline() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<!doctype html>\n"
                                + "<html lang=\"en\">\n"
                                + "  <body class=\"index\">\n"
                                + "    <div id=\"fb-root\"></div>\n"
                                + "    <script>(function(d, s, id) {\n"
                                + "      var js, fjs = d.getElementsByTagName(s)[0];\n"
                                + "      if (d.getElementById(id)) return;\n"
                                + "      js = d.createElement(s); js.id = id;\n"
                                + "      js.src = \"//connect.facebook.net/en_US/all.js#xfbml=1&appId=277385395761685\";\n"
                                + "      fjs.parentNode.insertBefore(js, fjs);\n"
                                + "    }(document, 'script', 'facebook-jssdk'));</script>"
                                + "  </body>\n"
                                + "</html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
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
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    public void shouldNotRaiseAlertGivenHtmlAssetIsInline() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"data:,\"></script>"
                                + "<link href=\"data:,\">"
                                + "</head><body></body></html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    private static HttpMessage buildMessage(String body) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://example.com/ HTTP/1.1");
        msg.setResponseBody(body);
        return msg;
    }
}
