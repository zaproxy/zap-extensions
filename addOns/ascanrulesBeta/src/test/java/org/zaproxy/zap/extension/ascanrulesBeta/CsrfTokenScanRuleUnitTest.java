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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class CsrfTokenScanRuleUnitTest extends ActiveScannerTest<CsrfTokenScanRule> {

    @Override
    protected CsrfTokenScanRule createScanner() {
        CsrfTokenScanRule rule = new CsrfTokenScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        setUpHttpSessionsParam();
        return rule;
    }

    @Test
    void shouldInitWithConfig() throws Exception {
        // Given
        CsrfTokenScanRule rule = new CsrfTokenScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        // When / Then
        assertDoesNotThrow(() -> rule.init(getHttpMessage(""), parent));
    }

    @Test
    void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        CsrfTokenScanRule rule = new CsrfTokenScanRule();
        HttpMessage msg = getHttpMessage("");
        // When / Then
        assertThrows(NullPointerException.class, () -> rule.init(msg, parent));
    }

    @Test
    void shouldHaveSessionIdsInConfig() throws Exception {
        // Given
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);
        // When
        List<String> sessionIds = sessionOptions.getDefaultTokensEnabled();
        // Then
        assertThat(sessionIds, is(not(empty())));
    }

    @Test
    void shouldNotProcessWithoutForm() throws Exception {
        // Given
        HttpMessage msg =
                getHttpMessage(
                        "GET",
                        "/",
                        "<html><input type=\"hidden\" name=\"customAntiCSRF\" value="
                                + Math.random()
                                + "></input></html>");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is not processed, no need to check antiCSRF without a form
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    void shouldNotProcessNonHtml() throws Exception {
        // Given
        HttpMessage msg =
                getHttpMessage(
                        "GET",
                        "/",
                        "function miscFunc() {\n"
                                + "\n"
                                + "YF = '<form method=\"POST\" action=\"miscEndPt\">\\n <input type=\"text\"></form>'\n"
                                + "\n"
                                + "return YF\n"
                                + "}");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/javascript");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is not processed, no need to check antiCSRF if not HTML
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    void shouldProcessWithoutCookie() throws Exception {
        // Given
        HttpMessage msg = getAntiCSRFCompatibleMessage();
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is processed
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertThat(httpMessagesSent.get(0).getCookieParams(), is(empty())); // 0 session cookies
    }

    @Test
    void shouldProcessWithOneSessionCookie() throws Exception {
        // Given
        HttpMessage msg = getAntiCSRFCompatibleMessage();
        TreeSet<HtmlParameter> cookies = new TreeSet<>();
        cookies.add(getCookieAs("JSESSIONID"));
        msg.setCookieParams(cookies);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is processed
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertThat(httpMessagesSent.get(0).getCookieParams(), hasSize(1)); // 1 session cookie
    }

    @Test
    void shouldProcessWithTwoSessionCookies() throws Exception {
        // Given
        HttpMessage msg = getAntiCSRFCompatibleMessage();
        TreeSet<HtmlParameter> cookies = new TreeSet<>();
        cookies.add(getCookieAs("JSESSIONID"));
        cookies.add(getCookieAs("SessId"));
        msg.setCookieParams(cookies);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is processed
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertThat(httpMessagesSent.get(0).getCookieParams(), hasSize(2)); // 2 session cookies
    }

    @Test
    void shouldProcessWithOtherCookie() throws Exception {
        // Given
        HttpMessage msg = getAntiCSRFCompatibleMessage();
        TreeSet<HtmlParameter> cookies = new TreeSet<>();
        cookies.add(getCookieAs("otherCookie"));
        msg.setCookieParams(cookies);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is processed
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertThat(httpMessagesSent.get(0).getCookieParams(), is(empty())); // 0 session cookies
    }

    @Test
    void shouldProcessWithTwoSessionCookiesAndOtherCookie() throws Exception {
        // Given
        HttpMessage msg = getAntiCSRFCompatibleMessage();
        TreeSet<HtmlParameter> cookies = new TreeSet<>();
        cookies.add(getCookieAs("JSESSIONID"));
        cookies.add(getCookieAs("SessId"));
        cookies.add(getCookieAs("otherCookie"));
        msg.setCookieParams(cookies);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is processed
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertThat(httpMessagesSent.get(0).getCookieParams(), hasSize(2)); // 2 session cookies
    }

    @Test
    void shouldNotProcessAtHighThresholdAndOutOfScope()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(false);

        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(equalTo(0))); // No messages sent
    }

    @Test
    void shouldProcessAtHighThresholdAndInScope()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(true);

        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.HIGH);
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldProcessAtMediumThresholdAndOutOfScope()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(false);
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        // Note: This Test leverages the context setup in a previous test
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldProcessAtMediumThresholdAndInScope()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(true);
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.MEDIUM);
        // Note: This Test leverages the context setup in a previous test
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldProcessAtLowThresholdAndOutOfScope()
            throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(false);
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        // Note: This Test leverages the context setup in a previous test
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldProcessAtLowThresholdAndInScope() throws HttpMalformedHeaderException, URIException {
        // Given
        HttpMessage msg = createMessage(true);
        rule.setConfig(new ZapXmlConfiguration());
        rule.setAlertThreshold(AlertThreshold.LOW);
        // Note: This Test leverages the context setup in a previous test
        rule.init(msg, parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(352)));
        assertThat(wasc, is(equalTo(9)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_05_CSRF.getValue())));
    }

    private HttpMessage createMessage(boolean isInScope)
            throws URIException, HttpMalformedHeaderException {
        HttpMessage msg =
                new HttpMessage() {

                    @Override
                    public HttpMessage cloneRequest() {
                        HttpMessage newMsg =
                                new HttpMessage() {

                                    @Override
                                    public boolean isInScope() {
                                        return isInScope;
                                    }
                                };

                        if (!this.getRequestHeader().isEmpty()) {
                            try {
                                newMsg.getRequestHeader()
                                        .setMessage(this.getRequestHeader().toString());
                            } catch (HttpMalformedHeaderException e) {
                                throw new RuntimeException(e);
                            }
                            newMsg.setRequestBody(this.getRequestBody().getBytes());
                        }
                        return newMsg;
                    }
                };

        HttpMessage compatMsg = getAntiCSRFCompatibleMessage();
        msg.setRequestHeader(compatMsg.getRequestHeader());
        msg.setRequestBody(compatMsg.getRequestBody());
        msg.setResponseHeader(compatMsg.getResponseHeader());
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "text/html");
        msg.setResponseBody(compatMsg.getResponseBody());

        return msg;
    }

    private void setUpHttpSessionsParam() {
        HttpSessionsParam sessionOptions = new HttpSessionsParam();
        sessionOptions.load(new ZapXmlConfiguration());
        Model.getSingleton().getOptionsParam().addParamSet(sessionOptions);
    }

    private HttpMessage getAntiCSRFCompatibleMessage() throws HttpMalformedHeaderException {
        return getHttpMessage(
                "GET",
                "/",
                "<html><form><input type=\"hidden\" name=\"customAntiCSRF\" value="
                        + Math.random()
                        + "></input></form></html>");
    }

    private HtmlParameter getCookieAs(String cookieName) {
        return new HtmlParameter(
                HtmlParameter.Type.cookie, cookieName, "FF4F838FDA9E1974DEEB4020AB6127FD");
    }
}
