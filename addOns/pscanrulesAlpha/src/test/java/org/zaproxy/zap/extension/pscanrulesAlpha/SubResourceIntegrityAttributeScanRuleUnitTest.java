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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class SubResourceIntegrityAttributeScanRuleUnitTest
        extends PassiveScannerTest<SubResourceIntegrityAttributeScanRule> {

    private HttpMessage message;

    @Override
    protected SubResourceIntegrityAttributeScanRule createScanner() {
        SubResourceIntegrityAttributeScanRule rule = new SubResourceIntegrityAttributeScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        return rule;
    }

    void setupMocks(boolean nodeFound) throws Exception {
        setUpZap();

        Model model = mock(Model.class, withSettings().lenient());
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class, withSettings().lenient());
        given(model.getSession()).willReturn(session);

        SiteMap siteMap = mock(SiteMap.class, withSettings().lenient());
        given(session.getSiteTree()).willReturn(siteMap);

        SiteNode node = mock(SiteNode.class, withSettings().lenient());
        if (nodeFound) {
            given(siteMap.findNode(any(URI.class))).willReturn(node);
        } else {
            given(siteMap.findNode(any(URI.class))).willReturn(null);
        }

        if (nodeFound) {
            HistoryReference historyRef = mock(HistoryReference.class);
            given(node.getHistoryReference()).willReturn(historyRef);
            message =
                    mock(HttpMessage.class, withSettings().lenient().defaultAnswer(RETURNS_MOCKS));
            given(message.isResponseFromTargetHost()).willReturn(true);
            given(historyRef.getHttpMessage()).willReturn(message);
            HttpResponseBody hrb = mock(HttpResponseBody.class, withSettings().lenient());
            given(message.getResponseBody()).willReturn(hrb);
            given(hrb.toString()).willReturn("foobar");
            // "foobar" SHA-384:
            // 3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06
        }
    }

    @Test
    void shouldNotRaiseAlertGivenIntegrityAttributeIsPresentInLinkElement()
            throws HttpMalformedHeaderException {
        // Given
        // From https://www.w3.org/TR/SRI/#use-casesexamples
        HttpMessage msg =
                buildMessage(
                        "<html><head><link href=\"https://site53.example.net/style.css\"\n"
                                + "      integrity=\"sha384-c2hhMzg0LSsvTTZrcmVkSmN4ZHNxa2N6QlVqTUx2cXlIYjFLL0pUaERYV3NCVnhNRWVaSEVhTUtFT0VjdDMzOVZJdFgxekI=\"\n"
                                + "      ></head><body></body></html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotIndicateElementGivenElementIsServedByTrustedDomains()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.example.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");
        rule.getConfig().setProperty(RuleConfigParam.RULE_DOMAINS_TRUSTED, "some.cdn.example.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldIndicateElementGivenElementIsServedByTrustedDomainsWhenPatternMismatches()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.example.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");
        rule.getConfig()
                .setProperty(RuleConfigParam.RULE_DOMAINS_TRUSTED, "https://some.cdn.example.com");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotRaiseAlertGivenCanonicalAttributeIsPresentInLinkElement()
            throws HttpMalformedHeaderException {
        // Given
        // From https://www.w3.org/TR/SRI/#use-casesexamples
        HttpMessage msg =
                buildMessage(
                        "<html><head><link href=\"https://dev.example.net/style.css\"\n"
                                + "rel=\"canonical\"\n"
                                + "      ></head><body></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotRaiseAlertGivenIntegrityAttributeIsPresentInScriptElement()
            throws HttpMalformedHeaderException {
        // Given
        // From https://www.w3.org/TR/SRI/#use-casesexamples
        HttpMessage msg =
                buildMessage(
                        "<html><head><script src=\"https://analytics-r-us.example.com/v1.0/include.js\"\n"
                                + "        integrity=\"sha384-c2hhMzg0LU1CTzVJRGZZYUU2YzZBYW85NG9acklPaUM2Q0dpU04ybjRRVWJITlBoems1WGhtMGRqWkxRcVRwTDBIelRVeGs=\"\n"
                                + "        ></script></head><body></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldRaiseAlertGivenIntegrityAttributeIsMissingForSupportedElement() throws Exception {
        // Given
        setupMocks(true);
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.get(0).getPluginId(), equalTo(rule.getPluginId()));
        assertThat(
                alertsRaised.get(0).getOtherInfo(),
                equalTo(
                        "The following hash was calculated (using base64 encoding of the output of the hash algorithm: SHA-384) for the script in question sha384-PJww2fZl501RXIQpYNSkUcg6ASX9Pec5LXs3IxrxDHLqWK7fzfiaV2W/kCr5Ps8G"));
    }

    @Test
    void shouldRaiseAlertGivenIntegrityAttributeIsMissingForSupportedElementScriptNodeNotFound()
            throws Exception {
        // Given
        setupMocks(false);
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.get(0).getPluginId(), equalTo(rule.getPluginId()));
        assertThat(alertsRaised.get(0).getOtherInfo(), equalTo(""));
    }

    @Test
    void
            shouldRaiseAlertGivenIntegrityAttributeIsMissingForSupportedElementScriptResponseNotFromTarget()
                    throws Exception {
        // Given
        setupMocks(true);
        given(message.isResponseFromTargetHost()).willReturn(false);
        HttpMessage msg =
                buildMessage(
                        "<html><head>"
                                + "<script src=\"https://some.cdn.com/v1.0/include.js\"></script>"
                                + "</head><body></body></html>");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getOtherInfo(), equalTo(""));
    }

    @Test
    void shouldIndicateElementWithoutIntegrityAttribute() throws Exception {
        // Given
        setupMocks(true);
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
    void shouldNotRaiseAlertGivenElementIsServedByCurrentDomain()
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
    void shouldRaiseAlertGivenElementIsServedBySubDomain() throws Exception {
        // Given
        setupMocks(true);
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
    void shouldNotRaiseAlertGivenElementIsServedRelatively() throws HttpMalformedHeaderException {
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
    void shouldNotRaiseAlertGivenElementIsInline() throws HttpMalformedHeaderException {
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
    void shouldIgnoreInvalidFormattedHostname() throws HttpMalformedHeaderException {
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
    void shouldNotRaiseAlertGivenHtmlAssetIsInline() throws HttpMalformedHeaderException {
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

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    private static HttpMessage buildMessage(String body) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://example.com/ HTTP/1.1");
        msg.setResponseBody(body);
        return msg;
    }
}
