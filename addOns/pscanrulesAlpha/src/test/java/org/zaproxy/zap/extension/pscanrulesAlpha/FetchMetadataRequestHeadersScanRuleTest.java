/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

class FetchMetadataRequestHeadersScanRuleTest
        extends PassiveScannerTest<FetchMetadataRequestHeadersScanRule> {
    private static final String HTTP_METHOD = "GET / HTTP/1.1\r\n";
    private static final String SFS_VALID_HEADER = "Sec-Fetch-Site: same-origin\r\n";
    private static final String SFS_INVALID_HEADER = "Sec-Fetch-Site: same\r\n";
    private static final String SFM_VALID_HEADER = "Sec-Fetch-Mode: navigate\r\n";
    private static final String SFM_INVALID_HEADER = "Sec-Fetch-Mode: socket\r\n";
    private static final String SFD_VALID_HEADER = "Sec-Fetch-Dest: audio\r\n";
    private static final String SFD_INVALID_HEADER = "Sec-Fetch-Dest: doc\r\n";
    private static final String SFU_VALID_HEADER = "Sec-Fetch-User: ?1\r\n";
    private static final String SFU_INVALID_HEADER = "Sec-Fetch-User: none\r\n";

    @Test
    void shouldRaiseSfsAlertGivenRequestDoesntSendSfsHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForMissingCase("Sec-Fetch-Site"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchSite.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    void shouldRaiseSfmAlertGivenRequestDoesntSendSfmHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForMissingCase("Sec-Fetch-Mode"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchMode.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    void shouldRaiseSfdAlertGivenRequestDoesntSendSfdHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForMissingCase("Sec-Fetch-Dest"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchDest.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    void shouldRaiseSfuAlertGivenRequestDoesntSendSfuHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForMissingCase("Sec-Fetch-User"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchUser.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    void shouldNotRaiseAlertGivenAllHeadersArePresentAndValid() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForMissingCase("none"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseSfsAlertGivenRequestSendsInvalidSfsHeaderValue() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForInvalidCase("Sec-Fetch-Site"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchSite.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("same"));
    }

    @Test
    void shouldRaiseSfmAlertGivenRequestSendsInvalidSfmHeaderValue() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForInvalidCase("Sec-Fetch-Mode"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchMode.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("socket"));
    }

    @Test
    void shouldRaiseSfdAlertGivenRequestSendsInvalidSfdHeaderValue() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForInvalidCase("Sec-Fetch-Dest"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchDest.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("doc"));
    }

    @Test
    void shouldRaiseSfuAlertGivenRequestSendsInvalidSfuHeaderValue() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForInvalidCase("Sec-Fetch-User"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getParam(),
                equalTo(FetchMetadataRequestHeadersScanRule.SecFetchUser.HEADER));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("none"));
    }

    @Test
    void shouldNotRaiseAlertGivenAllHeadersAreInLowerCase() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(generateRequestForInvalidCase("none"));

        // When
        scanHttpRequestSend(msg);

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        List<Alert> alerts = rule.getExampleAlerts();

        assertThat(alerts, hasSize(8));
        assertExampleAlert(alerts.get(0), "Sec-Fetch-Site Header is Missing", "90005-1");
        assertExampleAlert(alerts.get(1), "Sec-Fetch-Mode Header is Missing", "90005-2");
        assertExampleAlert(alerts.get(2), "Sec-Fetch-Dest Header is Missing", "90005-3");
        assertExampleAlert(alerts.get(3), "Sec-Fetch-User Header is Missing", "90005-4");
        assertExampleAlert(alerts.get(4), "Sec-Fetch-Site Header Has an Invalid Value", "90005-5");
        assertExampleAlert(alerts.get(5), "Sec-Fetch-Mode Header Has an Invalid Value", "90005-6");
        assertExampleAlert(alerts.get(6), "Sec-Fetch-Dest Header Has an Invalid Value", "90005-7");
        assertExampleAlert(alerts.get(7), "Sec-Fetch-User Header Has an Invalid Value", "90005-8");
    }

    private static void assertExampleAlert(Alert alert, String name, String alertRef) {
        assertThat(alert.getName(), equalTo(name));
        assertThat(alert.getAlertRef(), equalTo(alertRef));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_INFO));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_HIGH));
    }

    @Override
    protected FetchMetadataRequestHeadersScanRule createScanner() {
        return new FetchMetadataRequestHeadersScanRule();
    }

    private String generateRequestForMissingCase(String missingHeader) {
        switch (missingHeader) {
            case "Sec-Fetch-Site":
                return HTTP_METHOD + SFM_VALID_HEADER + SFD_VALID_HEADER + SFU_VALID_HEADER;
            case "Sec-Fetch-Mode":
                return HTTP_METHOD + SFS_VALID_HEADER + SFD_VALID_HEADER + SFU_VALID_HEADER;
            case "Sec-Fetch-Dest":
                return HTTP_METHOD + SFS_VALID_HEADER + SFM_VALID_HEADER + SFU_VALID_HEADER;
            case "Sec-Fetch-User":
                return HTTP_METHOD + SFS_VALID_HEADER + SFM_VALID_HEADER + SFD_VALID_HEADER;
            default:
                return HTTP_METHOD
                        + SFS_VALID_HEADER
                        + SFM_VALID_HEADER
                        + SFD_VALID_HEADER
                        + SFU_VALID_HEADER;
        }
    }

    private String generateRequestForInvalidCase(String invalidHeader) {
        switch (invalidHeader) {
            case "Sec-Fetch-Site":
                return HTTP_METHOD
                        + SFS_INVALID_HEADER
                        + SFM_VALID_HEADER
                        + SFD_VALID_HEADER
                        + SFU_VALID_HEADER;
            case "Sec-Fetch-Mode":
                return HTTP_METHOD
                        + SFS_VALID_HEADER
                        + SFM_INVALID_HEADER
                        + SFD_VALID_HEADER
                        + SFU_VALID_HEADER;
            case "Sec-Fetch-Dest":
                return HTTP_METHOD
                        + SFS_VALID_HEADER
                        + SFM_VALID_HEADER
                        + SFD_INVALID_HEADER
                        + SFU_VALID_HEADER;
            case "Sec-Fetch-User":
                return HTTP_METHOD
                        + SFS_VALID_HEADER
                        + SFM_VALID_HEADER
                        + SFD_VALID_HEADER
                        + SFU_INVALID_HEADER;
            default:
                return HTTP_METHOD
                        + "sec-fetch-site: same-origin\r\n"
                        + "sec-fetch-mode: navigate\r\n"
                        + "sec-fetch-dest: audio\r\n"
                        + "sec-fetch-user: ?1\r\n";
        }
    }
}
