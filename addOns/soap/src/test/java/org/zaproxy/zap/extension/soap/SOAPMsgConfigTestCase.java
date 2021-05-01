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

import com.predic8.wsdl.BindingOperation;
import com.predic8.wsdl.Definitions;
import com.predic8.wsdl.Port;
import java.util.HashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SOAPMsgConfigTestCase {

    private SOAPMsgConfig soapConfig;

    @BeforeEach
    public void setUp() {
        /* Empty configuration object. */
        soapConfig = new SOAPMsgConfig();
        soapConfig.setWsdl(new Definitions());
        soapConfig.setSoapVersion(1);
        soapConfig.setParams(new HashMap<>());
        soapConfig.setPort(new Port());
        soapConfig.setBindOp(new BindingOperation());
    }

    @Test
    public void isCompleteTest() {
        /* Positive case. */
        assertTrue(soapConfig.isComplete());

        /* Negative cases. */
        soapConfig.setWsdl(null);
        assertFalse(soapConfig.isComplete()); // Null WSDL.
        soapConfig.setWsdl(new Definitions());

        soapConfig.setSoapVersion(0);
        assertFalse(soapConfig.isComplete()); // SOAP version < 1
        soapConfig.setSoapVersion(3);
        assertFalse(soapConfig.isComplete()); // SOAP version > 2
        soapConfig.setSoapVersion(1);

        soapConfig.setParams(null);
        assertFalse(soapConfig.isComplete()); // Null params.
        soapConfig.setParams(new HashMap<>());

        soapConfig.setPort(null);
        assertFalse(soapConfig.isComplete()); // Null port.
        soapConfig.setPort(new Port());

        soapConfig.setBindOp(null);
        assertFalse(soapConfig.isComplete()); // Null binding operation.
        soapConfig.setBindOp(new BindingOperation());
    }
}
