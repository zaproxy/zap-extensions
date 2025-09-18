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
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.soap.SOAPActionSpoofingActiveScanRule.ResponseType;

class SOAPActionSpoofingActiveScanRuleTestCase {

    private HttpMessage originalMsg = new HttpMessage();
    private HttpMessage modifiedMsg = new HttpMessage();
    private SOAPActionSpoofingActiveScanRule rule = new SOAPActionSpoofingActiveScanRule();

    @BeforeEach
    void setUp() throws HttpMalformedHeaderException {
        /* Original. */
        Sample.setOriginalRequest(originalMsg);
        Sample.setOriginalResponse(originalMsg);
        /* Modified. */
        Sample.setOriginalRequest(modifiedMsg);
        Sample.setByeActionRequest(modifiedMsg);
        Sample.setByeResponse(modifiedMsg);
    }

    @Test
    void scanResponseTest() throws Exception {
        SOAPActionSpoofingActiveScanRule scanner = new SOAPActionSpoofingActiveScanRule();

        /* Positive cases. */
        ResponseType result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertEquals(ResponseType.SOAPACTION_EXECUTED, result);

        Sample.setOriginalResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertEquals(ResponseType.SOAPACTION_IGNORED, result);

        /* Negative cases. */
        result = scanner.scanResponse(new HttpMessage(), originalMsg);
        assertEquals(ResponseType.EMPTY_RESPONSE, result);

        Sample.setEmptyBodyResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertEquals(ResponseType.EMPTY_RESPONSE, result);

        Sample.setInvalidFormatResponse(modifiedMsg);
        result = scanner.scanResponse(modifiedMsg, originalMsg);
        assertEquals(ResponseType.INVALID_FORMAT, result);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(451)));
        assertThat(wasc, is(equalTo(0)));
        assertThat(tags.size(), is(equalTo(11)));

        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
    }
}
