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

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class SOAPActionSpoofingActiveScanRuleTestCase {

    private HttpMessage originalMsg = new HttpMessage();
    private HttpMessage modifiedMsg = new HttpMessage();

    @BeforeEach
    public void setUp() throws HttpMalformedHeaderException {
        /* Original. */
        Sample.setOriginalRequest(originalMsg);
        Sample.setOriginalResponse(originalMsg);
        /* Modified. */
        Sample.setOriginalRequest(modifiedMsg);
        Sample.setByeActionRequest(modifiedMsg);
        Sample.setByeResponse(modifiedMsg);
    }

    @Test
    public void scanResponseTest() throws Exception {
        SOAPActionSpoofingActiveScanRule scanner = new SOAPActionSpoofingActiveScanRule();

        /* Positive cases. */
        int result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertTrue(result == SOAPActionSpoofingActiveScanRule.SOAPACTION_EXECUTED);

        Sample.setOriginalResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertTrue(result == SOAPActionSpoofingActiveScanRule.SOAPACTION_IGNORED);

        /* Negative cases. */
        result = scanner.scanResponse(new HttpMessage(), originalMsg);
        assertTrue(result == SOAPActionSpoofingActiveScanRule.EMPTY_RESPONSE);

        Sample.setEmptyBodyResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertTrue(result == SOAPActionSpoofingActiveScanRule.EMPTY_RESPONSE);

        Sample.setInvalidFormatResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertTrue(result == SOAPActionSpoofingActiveScanRule.INVALID_FORMAT);
    }
}
