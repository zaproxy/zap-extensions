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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

public class SOAPXMLInjectionActiveScanRuleTestCase {

    @Test
    public void craftAttackMessageTest() throws Exception {
        HttpMessage originalMsg = new HttpMessage();
        Sample.setOriginalRequest(originalMsg);

        SOAPXMLInjectionActiveScanRule scanRule = new SOAPXMLInjectionActiveScanRule();
        HttpMessage actualMsg =
                scanRule.craftAttackMessage(originalMsg, "ns:args0", "updatedParamValue");

        HttpMessage expectedMsg = new HttpMessage();
        expectedMsg.setRequestBody(
                "<?xml version=\"1.0\" encoding= \"UTF-8\" ?>"
                        + "<s11:Envelope xmlns:s11=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                        + "<s11:Body>"
                        + "<ns:sayHelloWorld xmlns:ns=\"http://main.soaptest.org\">"
                        + "<ns:args0>updatedParamValue</ns:args0>"
                        + "</ns:sayHelloWorld>"
                        + "</s11:Body>"
                        + "</s11:Envelope>");
        assertThat(
                actualMsg.getRequestBody().toString(),
                is(equalTo(expectedMsg.getRequestBody().toString())));
    }
}
