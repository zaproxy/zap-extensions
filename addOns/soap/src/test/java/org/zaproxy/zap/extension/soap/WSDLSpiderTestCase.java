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

import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

public class WSDLSpiderTestCase {

    private HttpMessage wsdlMsg = new HttpMessage();

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
    public void parseResourceTest()
            throws NoSuchMethodException, SecurityException, IllegalAccessException,
                    IllegalArgumentException, InvocationTargetException {
        WSDLSpider spider = new WSDLSpider(new WSDLCustomParser(null));

        /* Positive case. */
        boolean result = spider.parseResourceWSDL(wsdlMsg, false);
        assertTrue(result);

        /* Negative cases. */
        result = spider.parseResourceWSDL(null, false); /* Null response. */
        assertFalse(result);

        result = spider.parseResourceWSDL(new HttpMessage(), false); /* Empty response. */
        assertFalse(result);

        wsdlMsg.setResponseBody("test");
        result = spider.parseResourceWSDL(wsdlMsg, false); /* Response with no-wsdl content. */
        assertFalse(result);
    }
}
