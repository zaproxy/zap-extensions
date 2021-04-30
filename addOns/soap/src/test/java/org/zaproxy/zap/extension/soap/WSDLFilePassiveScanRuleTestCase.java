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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class WSDLFilePassiveScanRuleTestCase {
    private HttpMessage wsdlMsg = new HttpMessage();

    private static void setContentType(HttpMessage msg, String contentType) {
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
    }

    @BeforeEach
    public void setUp() {
        try {
            wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
            wsdlMsg = Sample.setResponseHeaderContent(wsdlMsg);
            wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    void isWsdlTest()
            throws NoSuchMethodException, SecurityException, IllegalAccessException,
                    IllegalArgumentException, InvocationTargetException {
        WSDLFilePassiveScanRule scanner = new WSDLFilePassiveScanRule();
        /* Positive case. */
        boolean result = scanner.isWsdl(wsdlMsg);
        assertTrue(result);

        /* Negative cases. */
        result = scanner.isWsdl(null); /* Null response. */
        assertFalse(result);

        result = scanner.isWsdl(new HttpMessage()); /* Empty response. */
        assertFalse(result);
    }

    @Test
    void shouldNotAlertWhenWsdlFileNotFound() throws IOException {
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "text/xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        WSDLFilePassiveScanRule scanner = new WSDLFilePassiveScanRule();
        boolean result = scanner.isWsdl(wsdlMsg);
        assertFalse(result);
    }

    @Test
    void shouldAlertWhenWsdlFileFound() throws IOException {
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setRequestHeaderContent(wsdlMsg);
        setContentType(wsdlMsg, "text/xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        WSDLFilePassiveScanRule scanner = new WSDLFilePassiveScanRule();
        boolean result = scanner.isWsdl(wsdlMsg);
        assertTrue(result);
    }

    @Test
    void shouldAlertWhenWsdlXmlContentTypeFound() throws IOException {
        HttpMessage wsdlMsg = new HttpMessage();
        wsdlMsg = Sample.setOriginalRequest(wsdlMsg);
        setContentType(wsdlMsg, "application/wsdl+xml");
        wsdlMsg = Sample.setResponseBodyContent(wsdlMsg);
        WSDLFilePassiveScanRule scanner = new WSDLFilePassiveScanRule();
        boolean result = scanner.isWsdl(wsdlMsg);
        assertTrue(result);
    }
}
