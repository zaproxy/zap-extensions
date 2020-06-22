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

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class XFrameOptionsScanRuleUnitTest extends PassiveScannerTest<XFrameOptionScanRule> {

    private static final String BASE_RESOURCE_KEY = "pscanrules.xframeoptions.";
    private static final String NAME_HEADER_NOT_SET = BASE_RESOURCE_KEY + "missing.name";
    private static final String NAME_MULTIPLE_HEADERS = BASE_RESOURCE_KEY + "multiple.header.name";
    private static final String NAME_DEFINED_IN_META = BASE_RESOURCE_KEY + "compliance.meta.name";
    private static final String NAME_MALFORMED =
            BASE_RESOURCE_KEY + "compliance.malformed.setting.name";

    @Override
    protected XFrameOptionScanRule createScanner() {
        return new XFrameOptionScanRule();
    }

    @Test
    public void xframeOptionsDeny() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void xframeOptionsDenyLc() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: deny\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void xframeOptionsDenyMc() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: dEnY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void xframeOptionsSameOrigin() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: SAMEORIGIN\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void xframeOptionsAllowFrom() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: ALLOW-FROM https://www.anotherdomain.com/\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXframeOptions() throws HttpMalformedHeaderException {

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

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void noXframeOptionsErrorLow() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void noXframeOptionsErrorMed() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXframeOptionsErrorHigh() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXframeOptionsPlainTextLow() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("Blah");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void noXframeOptionsPlainTextMed() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("blah");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXframeOptionsPlainTextHigh() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("blah");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void multipleXframeOptions() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "X-Frame-Options: SAMEORIGIN\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MULTIPLE_HEADERS));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void xframeOptionsViaMetaTag() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody(
                "<html>" + "<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(2));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(1), hasNameLoadedWithKey(NAME_DEFINED_IN_META));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(
                alertsRaised.get(1).getEvidence(),
                equalTo("<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">"));
    }

    @Test
    public void xframeOptionsViaMetaTagAndHeader() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody(
                "<html>" + "<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">" + "</html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_DEFINED_IN_META));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("<meta http-equiv=\"X-Frame-Options\" content=\"DENY\">"));
    }

    @Test
    public void malformedXframeOptions() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "X-Frame-Options: STUFF\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MALFORMED));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("STUFF"));
    }

    @Test
    public void cspNoFaNoXframeOptions() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self';\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_HEADER_NOT_SET));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void cspWithFaNoXframeOptions() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void cspWithFaWithXframeOptions() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void cspWithFaWithBadXframeOptionsLow() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0), hasNameLoadedWithKey(NAME_MALFORMED));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_FRAME_OPTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("BAD"));
    }

    @Test
    public void cspWithFaWithBadXframeOptionsMedium() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void cspWithFaWithBadXframeOptionsHigh() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
                        + "X-Frame-Options: BAD\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        scanHttpResponseReceive(msg);

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
