package org.zaproxy.zap.extension.ascanrulesBeta;

import org.junit.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httpsessions.HttpSessionToken;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

public class CsrftokenscanTest extends ActiveScannerTest<Csrftokenscan> {

    @Override
    protected Csrftokenscan createScanner() {
        Csrftokenscan scanner = new Csrftokenscan();
        scanner.setConfig(getConfigWithHTTPSession("asp.net_sessionid", "aspsessionid", "siteserver", "cfid",
                "cftoken", "jsessionid", "phpsessid", "sessid", "sid", "viewstate", "zenid"));
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

    @Test(expected = NullPointerException.class)
    public void shouldFailToInitWithoutConfig() throws Exception {
        // Given
        Csrftokenscan scanner = new Csrftokenscan();
        // When
        scanner.init(getHttpMessage(""), parent);
        // Then = NullPointerException
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
        System.out.println(httpMessagesSent.get(0).getCookieParams().size());
        assertThat(httpMessagesSent.get(0).getCookieParams(), hasSize(2)); // 2 session cookies
    }

    private ZapXmlConfiguration getConfigWithHTTPSession(String... values) {

        ZapXmlConfiguration config = new ZapXmlConfiguration();

        HttpSessionsParam sessionOptions = new HttpSessionsParam();
        sessionOptions.load(config);

        ArrayList<HttpSessionToken> tokenList = new ArrayList<>();
        for (String value : values) {
            HttpSessionToken token = new HttpSessionToken();
            token.setName(value);
            token.setEnabled(true);
            tokenList.add(token);
        }
        sessionOptions.setDefaultTokens(tokenList);
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