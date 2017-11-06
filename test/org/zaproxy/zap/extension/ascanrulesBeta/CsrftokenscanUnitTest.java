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
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import org.junit.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

import java.util.List;
import java.util.TreeSet;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.empty;
import static org.junit.Assert.assertThat;

public class CsrftokenscanUnitTest extends ActiveScannerTest<Csrftokenscan> {

    @Override
    protected Csrftokenscan createScanner() {
        Csrftokenscan scanner = new Csrftokenscan();
        scanner.setConfig(getConfigWithHTTPSession());
        return scanner;
    }

    @Test
    public void shouldInitWithConfig() throws Exception {
        // Given
        Csrftokenscan scanner = new Csrftokenscan();
        scanner.setConfig(new ZapXmlConfiguration());
        // When
        scanner.init(getHttpMessage(""), parent);
        // Then = No exception.
    }

    @Test(expected = Exception.class)
    public void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        Csrftokenscan scanner = new Csrftokenscan();
        // When
        scanner.init(getHttpMessage(""), parent);
        // Then = Exception
    }

    @Test
    public void shouldHaveSessionIdsInConfig() throws Exception {
        // Given
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);
        // When
        List<String> sessionIds = sessionOptions.getDefaultTokensEnabled();
        // Then
        assertThat(sessionIds, is(not(empty())));
    }

    @Test
    public void shouldNotProcessWithoutForm() throws Exception {
        // Given
        HttpMessage msg = getHttpMessage("GET", "/", "<html><input type=\"hidden\" name=\"customAntiCSRF\" value=" + Math.random() + "></input></html>");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then the message is not processed, no need to check antiCSRF without a form
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    public void shouldProcessWithoutCookie() throws Exception {
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
    public void shouldProcessWithOneSessionCookie() throws Exception {
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
    public void shouldProcessWithTwoSessionCookies() throws Exception {
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
    public void shouldProcessWithOtherCookie() throws Exception {
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
    public void shouldProcessWithTwoSessionCookiesAndOtherCookie() throws Exception {
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

    private ZapXmlConfiguration getConfigWithHTTPSession() {

        ZapXmlConfiguration config = new ZapXmlConfiguration();
        HttpSessionsParam sessionOptions = new HttpSessionsParam();
        sessionOptions.load(config);
        Model.getSingleton().getOptionsParam().addParamSet(sessionOptions);

        return config;
    }

    private HttpMessage getAntiCSRFCompatibleMessage() throws HttpMalformedHeaderException {
        return getHttpMessage("GET", "/", "<html><form><input type=\"hidden\" name=\"customAntiCSRF\" value=" + Math.random() + "></input></form></html>");
    }

    private HtmlParameter getCookieAs(String cookieName) {
        return new HtmlParameter(HtmlParameter.Type.cookie, cookieName, "FF4F838FDA9E1974DEEB4020AB6127FD");
    }
}