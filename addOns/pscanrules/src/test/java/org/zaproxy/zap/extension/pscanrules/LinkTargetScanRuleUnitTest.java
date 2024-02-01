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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.Mock.Strictness;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link LinkTargetScanRule}. */
class LinkTargetScanRuleUnitTest extends PassiveScannerTest<LinkTargetScanRule> {

    private static final String HTML_CONTENT_TYPE = "text/html;charset=ISO-8859-1";
    private static final String TEXT_CONTENT_TYPE = "text/plain; charset=us-ascii";

    @Mock(strictness = Strictness.LENIENT)
    Model model;

    @Mock(strictness = Strictness.LENIENT)
    Session session;

    @BeforeEach
    void setup() {
        when(session.getContextsForUrl(anyString())).thenReturn(Collections.emptyList());
        when(model.getSession()).thenReturn(session);
        rule.setModel(model);
    }

    @Override
    protected LinkTargetScanRule createScanner() {
        LinkTargetScanRule rule = new LinkTargetScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        return rule;
    }

    private String getHeader(String contentType, int bodyLength) {
        return "HTTP/1.1 200 OK\r\n"
                + "Content-Type: "
                + contentType
                + "\r\n"
                + "Content-Length: "
                + bodyLength
                + "\r\n";
    }

    @Test
    void dontRaiseIssueWhenOnlyTargetBlank() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example.com\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenNoLinks() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenOneLinkNoTarget() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody("<html><a href=\"http://www.example.com\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetSameDomain() throws HttpMalformedHeaderException {
        // Given
        Context context1 = new Context(session, 0);
        context1.addIncludeInContextRegex("https://www.example.com.*");
        context1.addIncludeInContextRegex("https://www.example2.com.*");
        when(session.getContextsForUrl(anyString())).thenReturn(Arrays.asList(context1));
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"https://www.example2.com/\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetTrustedDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        rule.getConfig()
                .setProperty(RuleConfigParam.RULE_DOMAINS_TRUSTED, "https://www.example2.com/.*");
        // When
        msg.setResponseBody(
                "<html><a href=\"https://www.example2.com/page1\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void raiseIssueWhenOneLinkWithBlankTargetUntrustedDomain() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        rule.getConfig()
                .setProperty(RuleConfigParam.RULE_DOMAINS_TRUSTED, "https://www.example2.com/.*");
        // When
        msg.setResponseBody(
                "<html><a href=\"https://www.example3.com/page1\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"https://www.example3.com/page1\" rel=\"opener\" target=\"_blank\">link</a>"));
    }

    @Test
    void raiseIssueWhenOneLinkWithBlankTargetDifferentDomain() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"));
    }

    @Test
    void raiseIssueWhenOneLinkWithOtherTarget() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" rel=\"opener\" target=\"other\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"other\">link</a>"));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithOtherTargetHighThreshold()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" rel=\"opener\" target=\"other\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void raiseIssueWhenAreaWithBlankTargetDifferentDomain() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html> <img src=\"planets.gif\" width=\"145\" height=\"126\" alt=\"Planets\"  usemap=\"#planetmap\">"
                        + "<map name=\"planetmap\">"
                        + "  <area shape=\"rect\" coords=\"0,0,82,126\" href=\"https://www.example.com/sun.html\" rel=\"opener\" target=\"_blank\" alt=\"Sun\">"
                        + "  <area shape=\"circle\" coords=\"90,58,3\" href=\"https://www.example.com2/mercur.html\" rel=\"opener\" target=\"_blank\" alt=\"Mercury\">"
                        + "  <area shape=\"circle\" coords=\"124,58,8\" href=\"https://www.example.com/venus.html\" rel=\"opener\" target=\"_blank\" alt=\"Venus\">"
                        + "</map> </html>");

        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<area shape=\"circle\" coords=\"90,58,3\" href=\"https://www.example.com2/mercur.html\" rel=\"opener\" target=\"_blank\" alt=\"Mercury\">"));
    }

    @Test
    void dontRaiseIssueWhenAreaWithOtherTarget() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html> <img src=\"planets.gif\" width=\"145\" height=\"126\" alt=\"Planets\"  usemap=\"#planetmap\">"
                        + "<map name=\"planetmap\">"
                        + "  <area shape=\"rect\" coords=\"0,0,82,126\" href=\"https://www.example.com/sun.html\" rel=\"opener\" target=\"_blank\" alt=\"Sun\">"
                        + "  <area shape=\"circle\" coords=\"90,58,3\" href=\"mercur.html\" rel=\"opener\" target=\"_blank\"alt=\"Mercury\">"
                        + "  <area shape=\"circle\" coords=\"124,58,8\" href=\"https://www.example.com/venus.html\" rel=\"opener\" target=\"_blank\" alt=\"Venus\">"
                        + "</map> </html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenManyLinksWithBlankTargetSameDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "</html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void raiseIssueWhenManyLinksWithBlankTargetDifferentDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"
                        + "</html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a>"));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetNoopenerNoReferrer()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" target=\"_blank\" rel=\"noopener noreferrer\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetNoreferrerNoopener()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" target=\"_blank\" rel=\"noreferrer noopener\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenManyLinksWithOneBlankTargetSameDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html>"
                        + "<a href=\"http://www.example.com/1\">link</a>"
                        + "<a href=\"http://www.example.com/2\">link</a>"
                        + "<a href=\"http://www.example.com/3\" rel=\"opener\" target=\"other\">link</a>"
                        + "<a href=\"http://www.example.com/4\" target=\"_blank\" rel=\"noopener\">link</a>"
                        + "<a href=\"http://www.example.com/5\" target=\"_blank\" rel=\"noopener\">link</a>"
                        + "<a href=\"http://www.example.com/6\" target=\"_blank\">link</a>"
                        + "</html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void raiseIssueWhenManyLinksWithOneBlankTargetDifferentDomain()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html>"
                        + "<a href=\"http://www.example2.com/1\">link</a>"
                        + "<a href=\"http://www.example.com/2\">link</a>"
                        + "<a href=\"http://www.example2.com/3\">link</a>"
                        + "<a href=\"http://www.example2.com/4\" target=\"_blank\" rel=\"noopener noreferrer\">link</a>"
                        + "<a href=\"http://www.example2.com/5\" target=\"_blank\" rel=\"noreferrer noopener\">link</a>"
                        + "<a href=\"http://www.example2.com/6\" target=\"_blank\" rel=\"opener\">link</a>"
                        + "</html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"http://www.example2.com/6\" target=\"_blank\" rel=\"opener\">link</a>"));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetNonHtml() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example2.com\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(TEXT_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void dontRaiseIssueWhenOneLinkWithBlankTargetInContext() throws HttpMalformedHeaderException {
        // Given
        Context context = new Context(session, 0);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example2.com/.*");
        when(session.getContextsForUrl(anyString())).thenReturn(Arrays.asList(context));
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"https://www.example2.com/\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void raiseIssueWhenOneLinkWithBlankTargetNotInContext() throws HttpMalformedHeaderException {
        // Given
        Context context = new Context(session, 0);
        context.addIncludeInContextRegex("https://www.example.com/.*");
        context.addIncludeInContextRegex("https://www.example2.com/.*");
        when(session.getContextsForUrl(anyString())).thenReturn(Arrays.asList(context));
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        // When
        msg.setResponseBody(
                "<html><a href=\"http://www.example3.com/\" rel=\"opener\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "<a href=\"http://www.example3.com/\" rel=\"opener\" target=\"_blank\">link</a>"));
    }

    @Test
    void shouldNotFailIfLinkOrAreaDoesNotHaveHref() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        msg.setResponseBody("<html><a>link</a><area>area</area></html>");
        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldNotFailIfInvalidRegex() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        rule.getConfig().setProperty(RuleConfigParam.RULE_DOMAINS_TRUSTED, "[");
        msg.setResponseBody(
                "<html><a href=\"https://www.example2.com/page1\" target=\"_blank\">link</a></html>");
        msg.setResponseHeader(getHeader(HTML_CONTENT_TYPE, msg.getResponseBody().length()));
        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }
}
