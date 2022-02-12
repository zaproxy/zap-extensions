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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

class SourceCodeDisclosureScanRuleUnitTest
        extends PassiveScannerTest<SourceCodeDisclosureScanRule> {

    private static final String CODE_SQL = "insert into vulnerabilities values(";
    private static final String CODE_PHP = "<?php echo 'evils'; ?>";
    private static final String CODE_PHP2 = "<?=something; ?>";
    private static final String CODE_HTML = "<p>Innocent HTML</p>";
    private static final String URI = "https://www.example.com";

    private HttpMessage msg;

    @Override
    protected SourceCodeDisclosureScanRule createScanner() {
        return new SourceCodeDisclosureScanRule();
    }

    @BeforeEach
    void createHttpMessage() throws IOException {
        msg = new HttpMessage();
        msg.setRequestHeader("GET " + URI + " HTTP/1.1");
    }

    @Test
    void scannerNameShouldMatch() {
        // Quick test to verify scan rule name which is used in the policy dialog but not
        // alone in alerts
        assertThat(rule.getName(), is(getLocalisedString("name")));
    }

    @Test
    void givenJustHtmlBodyThenNoAlertRaised() {
        // Given
        msg.setResponseBody(CODE_HTML);

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {CODE_PHP, CODE_PHP2})
    void givenPHPCodeThenAlertRaised(String phpSnippet) {
        // Given
        msg.setResponseBody(wrapWithHTML(phpSnippet));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), phpSnippet, "PHP");
    }

    @Test
    void givenSQLCodeThenAlertRaised() {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_SQL));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
        assertAlertAttributes(alertsRaised.get(0), CODE_SQL, "SQL");
    }

    @Test
    void givenSQLAndPhpCodeThenOnlyOneAlertRaised() {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_SQL + CODE_PHP));

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldNotRaiseAlertOnCssRequest() throws Exception {
        // Given
        msg.getRequestHeader().setURI(new URI("https://www.example.com/assets/styles.css", true));
        msg.setResponseBody(wrapWithHTML(CODE_PHP));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnCssResponse() throws Exception {
        // Given
        msg.getRequestHeader().setURI(new URI("https://www.example.com/assets/styles", true));
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "text/css");
        msg.setResponseBody(wrapWithHTML(CODE_PHP));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertOnJavaScriptResponse() throws Exception {
        // Given
        msg.getRequestHeader().setURI(new URI("https://www.example.com/assets/scripts", true));
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "application/javascript");
        msg.setResponseBody("class a{ constructor(t,e)}");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"font.woff", "font.woff2", "font.ttf", "font.otf"})
    void shouldNotRaiseAlertOnValidPhpInFontRequest(String fileName) throws Exception {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_PHP2));
        msg.getRequestHeader().setURI(new URI("http://example.com/" + fileName, false));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"image.gif", "image.jpg", "image.png", "image.bmp"})
    void shouldNotRaiseAlertOnValidPhpInImageRequest(String fileName) throws Exception {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_PHP2));
        msg.getRequestHeader().setURI(new URI("http://example.com/" + fileName, false));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"font/ttf", "font/otf", "font/woff", "font/woff2"})
    void shouldNotRaiseAlertOnValidPhpWhenInFontResponse(String type) throws Exception {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_PHP2));
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, type);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"image/gif", "image/jpeg", "image/png", "image/bmp"})
    void shouldNotRaiseAlertOnValidPhpWhenInImageResponse(String type) throws Exception {
        // Given
        msg.setResponseBody(wrapWithHTML(CODE_PHP2));
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, type);
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertEquals(0, alertsRaised.size());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
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
