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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.httpsessions.HttpSessionsParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class TestInfoSessionIdURLUnitTest extends PassiveScannerTest<TestInfoSessionIdURL> {

    private HttpMessage msg;
    private static final String BODY = "Some text in the response, doesn't matter.\nLine 2\n";

    @Override
    protected TestInfoSessionIdURL createScanner() {

        TestInfoSessionIdURL scanner = new TestInfoSessionIdURL();
        //        scanner.setConfig(new ZapXmlConfiguration());
        setUpHttpSessionsParam();
        return scanner;
    }

    protected HttpMessage createHttpMessageWithRespBody(String responseBody)
            throws HttpMalformedHeaderException, URIException {

        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.setResponseBody(responseBody);
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "Content-Length: "
                        + responseBody.length()
                        + "\r\n");
        return msg;
    }

    @Test
    public void shouldHaveSessionIdsInConfig() throws Exception {

        // Given
        OptionsParam options = Model.getSingleton().getOptionsParam();
        HttpSessionsParam sessionOptions = options.getParamSet(HttpSessionsParam.class);

        // When
        List<String> sessionIds = new ArrayList<String>();
        if (sessionOptions != null) {
            sessionIds = sessionOptions.getDefaultTokensEnabled();
        }

        // Then
        assertThat(sessionIds, is(not(empty())));
    }

    @Test
    public void containsJSESSIONIDAsUrlParameter()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void containsJSESSIONIDAsUrlParameterInHTTPS()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/foo?jsessionid=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void noSessionIdInHTTPS() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void noSessionIDAsUrlParameterInHTTPS()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com/session/foo?session=false";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    public void containsJSESSIONIDAsUrlParameterInHTTPSOnCustomPort()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "https://example.com:4443/foo?jsessionid=1a530637289b03x07199de8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When

        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void containsJSESSIONIDInUrlBeforeParams()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred;JSESSIONID=asdfasdfasdf1234?foo=bar";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void containsCFIDAsUrlParameter() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://example.com/foo?CFiD=1A530637289A03B07199A44E8D531427";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    @Test
    public void containsCFIDInUrlBeforeParams() throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred;CFID=asdfasdfasdf1234?foo=bar";
        HttpMessage msg = createHttpMessageWithRespBody(BODY);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    //    @Test
    public void containsJSESSIONIDInResponseHREFParams()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred?foo=bar";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.w3schools.com/html/?jsessionid=1A530637289A03B07199A44E8D531427\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    //    @Test
    public void containsCFIDInResponseHREFBeforeParams()
            throws HttpMalformedHeaderException, URIException {

        // Given
        String testURI = "http://tld.gtld/fred?foo=bar";
        String body =
                "<html>\n<body>\n<h2>HTML Links</h2>\n"
                        + "<p><a href=\"https://www.w3schools.com/html/;CFID=asdfasdfasdf1234?foo=bar\">Testing ZAP</a>"
                        + "</p>\n"
                        + "</body>\n</html>";
        HttpMessage msg = createHttpMessageWithRespBody(body);
        msg.getRequestHeader().setURI(new URI(testURI, false));

        // When
        rule.scanHttpRequestSend(msg, -1);

        // Then
        assertEquals(1, alertsRaised.size());
    }

    private void setUpHttpSessionsParam() {
        HttpSessionsParam sessionOptions = new HttpSessionsParam();
        sessionOptions.load(new ZapXmlConfiguration());
        Model.getSingleton().getOptionsParam().addParamSet(sessionOptions);
    }
}
