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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.soap.SOAPActionSpoofingActiveScanRule.ResponseType;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;

class SOAPActionSpoofingActiveScanRuleTestCase
        extends ActiveScannerTestUtils<SOAPActionSpoofingActiveScanRule> {

    private HttpMessage originalMsg = new HttpMessage();
    private HttpMessage modifiedMsg = new HttpMessage();

    @Override
    protected SOAPActionSpoofingActiveScanRule createScanner() {
        return new SOAPActionSpoofingActiveScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionImportWSDL());
    }

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        super.setUp();
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
        assertThat(tags.size(), is(equalTo(13)));

        assertThat(
                tags.containsKey(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(true)));
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
                tags.get(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getTag()),
                is(equalTo(CommonAlertTag.API_2023_API10_UNSAFE_CONSUMPTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A05_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlerts() {
        // Given
        String otherInfo =
                Constant.messages.getString(
                        "soap.soapactionspoofing.alertInfo",
                        "1",
                        "GetBalance",
                        "AdminCloseAccount");
        // When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(3));
        assertExampleAlert(
                alerts.get(0), "90026-1", Alert.RISK_MEDIUM, "soapaction_executed", otherInfo);
        assertExampleAlert(alerts.get(1), "90026-2", Alert.RISK_LOW, "fault_code", otherInfo);
        assertExampleAlert(
                alerts.get(2), "90026-3", Alert.RISK_INFO, "soapaction_ignored", otherInfo);
    }

    private static void assertExampleAlert(
            Alert alert, String alertRef, int risk, String responseKey, String otherInfo) {
        assertThat(alert.getAlertRef(), is(equalTo(alertRef)));
        assertThat(alert.getRisk(), is(equalTo(risk)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getCweId(), is(equalTo(451)));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                Constant.messages.getString(
                                                "soap.soapactionspoofing." + responseKey)
                                        + otherInfo)));
    }
}
