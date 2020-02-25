/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

public class SourceCodeDisclosureScannerUnitTest
        extends PassiveScannerTest<SourceCodeDisclosureScanner> {

    private static final String CODE_SQL = "insert into vulnerabilities values(";
    private static final String CODE_PHP = "<?php echo 'evils'; ?>";
    private static final String CODE_HTML = "<p>Innocent HTML</p>";
    private static final String URI = "https://www.example.com";

    private HttpMessage msg;

    @Override
    protected SourceCodeDisclosureScanner createScanner() {
        return new SourceCodeDisclosureScanner();
    }

    @Before
    public void createHttpMessage() throws IOException {
        msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
    }

    @Test
    public void scannerNameShouldMatch() {
        // Quick test to verify scanner name which is used in the policy dialog but not
        // alone in alerts
        assertThat(rule.getName(), is(getLocalisedString("name")));
    }

    @Test
    public void givenJustHtmlBodyThenNoAlertRaised() {
        // Given
        msg.setResponseBody(CODE_HTML);

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    public void givenPHPCodeThenAlertRaised() {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_PHP));

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), CODE_PHP, "PHP");
    }

    @Test
    public void givenSQLCodeThenAlertRaised() {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_SQL));

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), CODE_SQL, "SQL");
    }

    @Test
    public void givenSQLAndPhpCodeThenOnlyOneAlertRaised() {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_SQL + CODE_PHP));

        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    private String wrapWithHTML(String code) {
        return CODE_HTML + code + CODE_HTML;
    }

    private void assertAlertAttributes(Alert alert, String evidence, final String language) {
        assertThat(alert.getRisk(), is(Alert.RISK_MEDIUM));
        assertThat(alert.getConfidence(), is(Alert.CONFIDENCE_MEDIUM));
        assertThat(alert.getName(), is(getLocalisedString("name") + " - " + language));
        assertThat(alert.getDescription(), is(getLocalisedString("desc") + " - " + language));
        assertThat(alert.getUri(), is(URI));
        assertThat(alert.getOtherInfo(), is(getLocalisedString("extrainfo", evidence)));
        assertThat(alert.getSolution(), is(getLocalisedString("soln")));
        assertThat(alert.getReference(), is(getLocalisedString("refs")));
        assertThat(alert.getEvidence(), is(evidence));
        assertThat(alert.getCweId(), is(540));
        assertThat(alert.getWascId(), is(13));
    }

    private String getLocalisedString(String key, Object... params) {
        return Constant.messages.getString("pscanalpha.sourcecodedisclosure." + key, params);
    }
}
