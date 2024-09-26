/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import static org.hamcrest.Matchers.lessThan;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link PolyfillCdnScriptScanRule}. */
class PolyfillCdnScriptScanRuleUnitTest extends PassiveScannerTest<PolyfillCdnScriptScanRule> {

    @Override
    protected PolyfillCdnScriptScanRule createScanner() {
        PolyfillCdnScriptScanRule rule = new PolyfillCdnScriptScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        return rule;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        List<Alert> exampleAlerts = rule.getExampleAlerts();
        // Then
        assertThat(exampleAlerts.size(), is(equalTo(2)));
        assertThat(exampleAlerts.get(0).getCweId(), is(equalTo(829)));
        assertThat(exampleAlerts.get(0).getWascId(), is(equalTo(15)));
        assertThat(exampleAlerts.get(0).getConfidence(), is(equalTo(3)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A06_VULN_COMP.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A09_VULN_COMP.getValue())));
        assertThat(exampleAlerts.get(1).getConfidence(), is(equalTo(1)));
    }

    @Test
    void noScripts() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void noPollyfillScripts() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<script src=\"https://www.example.com/script1\"/>"
                        + "<script src=\"https://www.example.com/script2\"/>"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://polyfill.io",
                "https://bootcdn.net",
                "https://bootcss.com",
                "https://staticfile.net",
                "https://staticfile.org",
                "https://unionadjs.com",
                "https://xhsbpza.com",
                "https://union.macoms.la",
                "https://newcrbpc.com",
                "http://io.bootCdn.net",
                "http://xxx.bOoTcSs.com",
                "hTTP://staticfile.net",
                "Http://StaticFile.org",
                "http://unionAdjs.com",
                "http://xhsbpza.com",
                "http://aaa.union.macoms.LA",
                "HTTP://aa.bb.cc.newcrbpc.com"
            })
    void polyfillScriptInHeader(String domain) throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<script src=\"https://www.example.com/script1\"/>"
                        + "<script src=\""
                        + domain
                        + "/script2\"/>"
                        + "</head>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(domain + "/script2"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("<script src=\"" + domain + "/script2\"/>"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://polyfill.io",
                "https://bootcdn.net",
                "https://bootcss.com",
                "https://staticfile.net",
                "https://staticfile.org",
                "https://unionadjs.com",
                "https://xhsbpza.com",
                "https://union.macoms.la",
                "https://newcrbpc.com",
                "http://io.bootCdn.net",
                "http://xxx.bOoTcSs.com",
                "hTTP://staticfile.net",
                "Http://StaticFile.org",
                "http://unionAdjs.com",
                "http://xhsbpza.com",
                "http://aaa.union.macoms.LA",
                "HTTP://aa.bb.cc.newcrbpc.com"
            })
    void polyfillScriptInBody(String domain) throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<script src=\"https://www.example.com/script1\"/>"
                        + "</head>"
                        + "<body>"
                        + "<script src=\""
                        + domain
                        + "/script2\"/>"
                        + "</body>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(domain + "/script2"));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("<script src=\"" + domain + "/script2\"/>"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://polyfill.io",
                "https://bootcdn.net",
                "https://bootcss.com",
                "https://staticfile.net",
                "https://staticfile.org",
                "https://unionadjs.com",
                "https://xhsbpza.com",
                "https://union.macoms.la",
                "https://newcrbpc.com",
                "http://bootCdn.net",
                "http://bOoTcSs.com",
                "hTTP://staticfile.net",
                "Http://StaticFile.org",
                "http://unionAdjs.com",
                "http://xhsbpza.com",
                "http://union.macoms.LA",
                "HTTP://newcrbpc.com"
            })
    void polyfillScriptInScriptBody(String domain) throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseBody(
                "<html>"
                        + "<head>"
                        + "<script src=\"https://www.example.com/script1\"/>"
                        + "</head>"
                        + "<body>"
                        + "<script>"
                        + " // "
                        + domain
                        + "/v3/polyfill.min.js"
                        + "</script>"
                        + "</body>"
                        + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(domain + "/v3/polyfill.min.js"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(1));
    }

    @Test
    void shouldRunQuickly() throws Exception {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.bbc.com/ HTTP/1.1");
        msg.setResponseBody(this.getHtml("bbc.html"));
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        long start = System.currentTimeMillis();
        scanHttpResponseReceive(msg);
        long end = System.currentTimeMillis();

        assertThat(alertsRaised.size(), equalTo(0));
        assertThat(end - start, lessThan(275L));
    }
}
