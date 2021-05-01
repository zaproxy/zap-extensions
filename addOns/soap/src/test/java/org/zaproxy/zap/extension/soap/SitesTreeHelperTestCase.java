/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

public class SitesTreeHelperTestCase extends TestUtils {
    HttpMessage message;

    @BeforeEach
    public void setup() throws Exception {
        setUpZap();
        message = new HttpMessage();
    }

    @Test
    public void getNodeNameForSoapV1Message() throws Exception {
        // Given
        Sample.setOriginalRequest(message);
        // When
        String nodeName = SitesTreeHelper.getNodeName(message);
        // Then
        assertEquals(nodeName, "sayHelloWorld (v1.1)");
    }

    @Test
    public void getNodeNameForSoapV2Message() throws Exception {
        // Given
        Sample.setSoapVersionTwoRequest(message);
        // When
        String nodeName = SitesTreeHelper.getNodeName(message);
        // Then
        assertEquals(nodeName, "sayHelloWorld (v1.2)");
    }
}
