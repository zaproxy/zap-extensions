/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;

class ApplicationErrorScanRuleBundledStringsUnitTest
        extends PassiveScannerTest<ApplicationErrorScanRule> {

    private static final String URI = "https://www.example.com/test/";
    private static final String REQUEST_HEADER = format("GET %s HTTP/1.1", URI);

    @Override
    protected ApplicationErrorScanRule createScanner() {
        return new ApplicationErrorScanRule();
    }

    @Test
    void shouldRaiseAlertForResponseCodeOkAndExpressPayloadDetected()
            throws HttpMalformedHeaderException {
        // Given
        String expectedEvidence = "SyntaxError: Unexpected token";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(REQUEST_HEADER);
        msg.setResponseHeader(createResponseHeader(HttpStatusCode.OK));
        given(passiveScanData.isPage500(any())).willReturn(false);
        given(passiveScanData.isPage404(any())).willReturn(false);
        msg.setResponseBody(
                "<!DOCTYPE html>\n"
                        + "<html lang=\"en\">\n"
                        + "<head>\n"
                        + "<meta charset=\"utf-8\">\n"
                        + "<title>Error</title>\n"
                        + "</head>\n"
                        + "<body>\n"
                        + "<pre>SyntaxError: Unexpected token <br> in JSON at position 98<br> &nbsp; \n"
                        + "...\n"
                        + "</pre>\n"
                        + "</body>\n"
                        + "</html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        Alert result = alertsRaised.get(0);
        assertThat(result.getEvidence(), equalTo(expectedEvidence));
        validateAlert(result);
    }

    private static void validateAlert(Alert alert) {
        assertThat(alert.getPluginId(), equalTo(90022));
        assertThat(alert.getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alert.getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getUri(), equalTo(URI));
    }

    private static String createResponseHeader(int code) {
        return format("HTTP/1.1 %d\r\n", code);
    }
}
