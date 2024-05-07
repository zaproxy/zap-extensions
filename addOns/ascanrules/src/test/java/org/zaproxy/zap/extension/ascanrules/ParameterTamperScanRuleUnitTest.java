/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.SimpleWebServer.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ParameterTamperScanRule}. */
class ParameterTamperScanRuleUnitTest extends ActiveScannerTest<ParameterTamperScanRule> {

    @Override
    protected ParameterTamperScanRule createScanner() {
        return new ParameterTamperScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(472)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
    }

    @Test
    void shouldNotContinueScanningIfFirstResponseIsNotOK() throws Exception {
        // Given
        rule.init(getHttpMessage("/?a=b"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldContinueScanningIfFirstResponseIsOK() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, "");
                    }
                });
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfAttackResponseIsAlwaysTheSame() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, "Default Response");
                    }
                });
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfAttackResponseIsNotOkNorServerError() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {

                    private boolean showDefaultResponse = true;

                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (showDefaultResponse) {
                            showDefaultResponse = false;
                            return newFixedLengthResponse(
                                    Response.Status.OK, NanoHTTPD.MIME_HTML, "Default Response");
                        }
                        return newFixedLengthResponse(
                                Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
                    }
                });
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfAttackResponseIsServerErrorWithUnknownErrorMessage() throws Exception {
        // Given
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/");
        nano.addHandler(serverErrorOnAttack);
        serverErrorOnAttack.setError("Not an error message the scanner knows...");
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfAttackResponseContainsJavaServletError() throws Exception {
        // Given
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/", 2);
        nano.addHandler(serverErrorOnAttack);
        serverErrorOnAttack.setError("javax.servlet.Class invoke exception");
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(4));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("javax.servlet.Class")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("@")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("")));
    }

    @Test
    void shouldAlertIfAttackResponseContainsVbScriptError() throws Exception {
        // Given
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/", 2);
        nano.addHandler(serverErrorOnAttack);
        serverErrorOnAttack.setError("Microsoft VBScript error");
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(4));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("Microsoft VBScript error")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("@")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("")));
    }

    @Test
    void shouldNotAlertIfAttackResponseDoesNotContainsJavaServletError() throws Exception {
        // Given
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/");
        nano.addHandler(serverErrorOnAttack);
        serverErrorOnAttack.setError("javax.servlet.NotAnException");
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Microsoft VBScript error",
                "Microsoft OLE DB Provider for ODBC Drivers error",
                "ODBC Drivers error",
                "Microsoft JET Database Engine error",
                " on line <b>",
                "Apache Tomcat/8.0.27 - Error report</title> ... <h1>HTTP Status 500 - Internal Server Error"
            })
    void shouldAlertWithLowConfidenceIfAttackResponseContainsOtherKnownServerErrors(String error)
            throws Exception {
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/");
        nano.addHandler(serverErrorOnAttack);

        // Given
        serverErrorOnAttack.setError(error);
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(error, httpMessagesSent, hasSize(2));
        assertThat(error, alertsRaised, hasSize(1));
        assertThat(error, alertsRaised.get(0).getEvidence(), is(equalTo(error)));
        assertThat(error, alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(
                error,
                alertsRaised.get(0).getAttack(),
                is(equalTo(""))); // Parameter empty, no attack value.
        assertThat(error, alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(error, alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(error, alertsRaised.get(0).getOtherInfo(), is(equalTo("")));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();

        // Then
        assertThat(alerts.size(), is(equalTo(1)));

        Alert alert = alerts.get(0);
        Map<String, String> tags1 = alert.getTags();
        assertThat(tags1.size(), is(equalTo(3)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(tags1, hasKey("CWE-472"));
        assertThat(
                tags1.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags1.containsKey(CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN.getTag()),
                is(equalTo(true)));
    }

    private static class ServerErrorOnAttack extends NanoServerHandler {

        private final int totalAttacks;
        private int count = 0;
        private String error;

        public ServerErrorOnAttack(String path) {
            this(path, 0);
        }

        public ServerErrorOnAttack(String path, int totalAttacks) {
            super(path);
            this.totalAttacks = totalAttacks;
        }

        public void setError(String error) {
            this.error = error;
            this.count = 0;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            if (count <= totalAttacks) {
                count++;
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_HTML, "Default Response");
            }
            return newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR, NanoHTTPD.MIME_HTML, error);
        }
    }
}
