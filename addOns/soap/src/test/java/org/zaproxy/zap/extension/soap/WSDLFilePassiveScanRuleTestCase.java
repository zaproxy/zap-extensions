/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

class WSDLFilePassiveScanRuleTestCase extends PassiveScannerTestUtils<WSDLFilePassiveScanRule> {

    @Override
    protected WSDLFilePassiveScanRule createScanner() {
        return new WSDLFilePassiveScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionImportWSDL());
    }

    private static void setContentType(HttpMessage msg, String contentType) {
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
    }

    @Test
    void isWsdlTest()
            throws NoSuchMethodException, SecurityException, IllegalAccessException,
                    IllegalArgumentException, InvocationTargetException, IOException {

        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        wsdlMsg = Sample.setResponseHeaderContent(wsdlMsg);
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);

        /* Positive case. */
        boolean result = rule.isWsdl(wsdlMsg);
        assertTrue(result);

        /* Negative cases. */
        result = rule.isWsdl(null); /* Null response. */
        assertFalse(result);

        result = rule.isWsdl(new HttpMessage()); /* Empty response. */
        assertFalse(result);
    }

    @Test
    void shouldNotIdentifyWsdlWhenWsdlFileNotFound() throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "text/xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertFalse(result);
    }

    @Test
    void shouldNotIdentifyWsdlWhenWsdlFileIsHtml() throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "text/html");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertFalse(result);
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/xml", "application/wsdl+xml"})
    void shouldAlertWhenWsdlResponseStatus200(String contentType) throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        setContentType(wsdlMsg, contentType);
        wsdlMsg.getResponseHeader().setStatusCode(200);
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        scanHttpResponseReceive(wsdlMsg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/xml", "application/wsdl+xml"})
    void shouldNotAlertWhenWsdlResponseStatus500(String contentType) throws IOException {
        // Given
        given(passiveScanData.isPage500(any())).willReturn(true);
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        setContentType(wsdlMsg, contentType);
        wsdlMsg.getResponseHeader().setStatusCode(500);
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        scanHttpResponseReceive(wsdlMsg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/xml", "application/wsdl+xml"})
    void shouldNotAlertWhenWsdlResponseStatus404(String contentType) throws IOException {
        // Given
        given(passiveScanData.isPage404(any())).willReturn(true);
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        setContentType(wsdlMsg, contentType);
        wsdlMsg.getResponseHeader().setStatusCode(404);
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        scanHttpResponseReceive(wsdlMsg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldIdentifyWsdlWhenWsdlFileFound() throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        setContentType(wsdlMsg, "text/xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertTrue(result);
    }

    @Test
    void shouldIdentifyWsdlWhenWsdlXmlContentTypeFound() throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "application/wsdl+xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertTrue(result);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"http://example.com/service.asmx?wsdl", "http://example.com/service.wsdl"})
    void shouldIdentifyWsdlWhenWsdlUrlFoundRegardlessOfContentType(String url) throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "text/plain");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        wsdlMsg.getRequestHeader().setURI(new URI(url, true));
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertTrue(result);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"http://example.com/service.asmx?wsdl", "http://example.com/service.wsdl"})
    void shouldNotIdentifyWsdlWhenWsdlUrlFoundIfHtmlContentType(String url) throws IOException {
        // Given
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "text/html");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        wsdlMsg.getRequestHeader().setURI(new URI(url, true));
        // When
        boolean result = rule.isWsdl(wsdlMsg);
        // Then
        assertFalse(result);
    }
}
