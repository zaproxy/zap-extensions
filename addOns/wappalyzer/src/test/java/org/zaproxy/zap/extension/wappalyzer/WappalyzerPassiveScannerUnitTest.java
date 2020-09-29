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
package org.zaproxy.zap.extension.wappalyzer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.List;
import java.util.Optional;
import org.apache.commons.lang.StringUtils;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

public class WappalyzerPassiveScannerUnitTest
        extends PassiveScannerTestUtils<WappalyzerPassiveScanner> {

    WappalyzerApplicationTestHolder defaultHolder;

    public WappalyzerApplicationTestHolder getDefaultHolder() {
        if (defaultHolder == null) {
            try {
                defaultHolder = new WappalyzerApplicationTestHolder();
                WappalyzerJsonParser parser = new WappalyzerJsonParser();
                WappalyzerData result = parser.parseAppsJson("apps.json");
                defaultHolder.setApplications(result.getApplications());
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        return defaultHolder;
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWappalyzer());
    }

    @Override
    protected WappalyzerPassiveScanner createScanner() {
        getDefaultHolder().resetApplicationsToSite();
        return new WappalyzerPassiveScanner(getDefaultHolder());
    }

    @Test
    public void testApacheWithPhp() throws HttpMalformedHeaderException {
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.php HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" + "Server: Apache\n" + "X-Powered-By: PHP/5.6.34");

        scan(msg);

        assertFoundAppCount("https://www.example.com", 2);
        assertFoundApp("https://www.example.com", "Apache");
        assertFoundApp("https://www.example.com", "PHP", "5.6.34");
    }

    @Test
    public void shouldMatchScriptElement() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                "<html>"
                        + "<script type='text/javascript' src='libs/modernizr.min.js?ver=4.1.1'>"
                        + "</script>"
                        + "</html>");

        // When
        scan(msg);

        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Modernizr");
    }

    @Test
    public void shouldNotMatchScriptElementContentIfNotOnScriptElement()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody("<html><body>libs/modernizr.min.js?ver=4.1.1</body></html>");

        // When
        scan(msg);

        // Then
        assertNull(getDefaultHolder().getAppsForSite("https://www.example.com"));
    }

    @Test
    public void shouldNotMatchOnNontextResponse() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/x-icon");
        // Purposefully set the body to something that should match but be ignored
        msg.setResponseBody("<html><script src=\"/bitrix/js\"></script></html>");
        // When
        scan(msg);
        // Then
        assertNull(getDefaultHolder().getAppsForSite("https://www.example.com"));
    }

    @Test
    public void shouldMatchOnNontextResponseWhenHeaderMatches()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/x-icon");
        msg.getResponseHeader().setHeader("X-Powered-CMS", "Bitrix Site Manager");
        // Purposefully set the body to something that should match but be ignored
        msg.setResponseBody("<html><script src=\"/bitrix/js\"></script></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 2);
        assertFoundApp("https://www.example.com", "1C-Bitrix"); // Matched
        assertFoundApp("https://www.example.com", "PHP"); // Implied
    }

    private void scan(HttpMessage msg) {
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));
    }

    private HttpMessage makeHttpMessage() throws HttpMalformedHeaderException {
        HttpMessage httpMessage = new HttpMessage();

        HistoryReference ref = mock(HistoryReference.class);
        given(ref.getSiteNode()).willReturn(mock(SiteNode.class));

        httpMessage.setHistoryRef(ref);

        httpMessage.setRequestHeader("GET https://www.example.com/ HTTP/1.1");
        httpMessage.setResponseHeader("HTTP/1.1 200 OK");
        httpMessage.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
        return httpMessage;
    }

    private void assertFoundAppCount(String site, int appCount) {
        List<ApplicationMatch> appsForSite = getDefaultHolder().getAppsForSite(site);
        assertThat(appsForSite, notNullValue());
        assertThat(appsForSite.size(), is(appCount));
    }

    private void assertFoundApp(String site, String appName) {
        assertFoundApp(site, appName, null);
    }

    private void assertFoundApp(String site, String appName, String version) {
        List<ApplicationMatch> appsForSite = getDefaultHolder().getAppsForSite(site);
        assertThat(appsForSite, notNullValue());

        Optional<ApplicationMatch> app =
                appsForSite.stream()
                        .filter(a -> StringUtils.equals(a.getApplication().getName(), appName))
                        .findFirst();

        assertThat("Application '" + appName + "' not present", app.isPresent(), is(true));
        if (version != null) {
            assertThat(app.get().getVersion(), is(version));
        }
    }
}
