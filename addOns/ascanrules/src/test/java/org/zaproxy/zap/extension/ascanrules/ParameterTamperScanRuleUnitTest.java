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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ParameterTamperScanRule}. */
public class ParameterTamperScanRuleUnitTest extends ActiveScannerTest<ParameterTamperScanRule> {

    @Override
    protected ParameterTamperScanRule createScanner() {
        return new ParameterTamperScanRule();
    }

    @Test
    public void shouldNotContinueScanningIfFirstResponseIsNotOK() throws Exception {
        // Given
        rule.init(getHttpMessage("/?a=b"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldContinueScanningIfFirstResponseIsOK() throws Exception {
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
    public void shouldNotAlertIfAttackResponseIsAlwaysTheSame() throws Exception {
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
    public void shouldNotAlertIfAttackResponseIsNotOkNorServerError() throws Exception {
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
    public void shouldNotAlertIfAttackResponseIsServerErrorWithUnknownErrorMessage()
            throws Exception {
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
    public void shouldAlertIfAttackResponseContainsJavaServletError() throws Exception {
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
    public void shouldNotAlertIfAttackResponseDoesNotContainsJavaServletError() throws Exception {
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

    @Test
    public void shouldAlertWithLowConfidenceIfAttackResponseContainsOtherKnownServerErrors()
            throws Exception {
        ServerErrorOnAttack serverErrorOnAttack = new ServerErrorOnAttack("/");
        nano.addHandler(serverErrorOnAttack);

        String[] serverErrors = {
            "Microsoft VBScript error",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "ODBC Drivers error",
            "Microsoft JET Database Engine error",
            " on line <b>",
            "Apache Tomcat/8.0.27 - Error report</title> ... <h1>HTTP Status 500 - Internal Server Error"
        };

        for (String serverError : serverErrors) {
            // Given
            serverErrorOnAttack.setError(serverError);
            rule.init(getHttpMessage("/?p=v"), parent);
            // When
            rule.scan();
            // Then
            assertThat(serverError, httpMessagesSent, hasSize(2));
            assertThat(serverError, alertsRaised, hasSize(1));
            assertThat(serverError, alertsRaised.get(0).getEvidence(), is(equalTo(serverError)));
            assertThat(serverError, alertsRaised.get(0).getParam(), is(equalTo("p")));
            assertThat(
                    serverError,
                    alertsRaised.get(0).getAttack(),
                    is(equalTo(""))); // Parameter empty, no attack value.
            assertThat(serverError, alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
            assertThat(
                    serverError,
                    alertsRaised.get(0).getConfidence(),
                    is(equalTo(Alert.CONFIDENCE_LOW)));
            assertThat(serverError, alertsRaised.get(0).getOtherInfo(), is(equalTo("")));

            // Clean up for next error
            rule = createScanner();
            httpMessagesSent.clear();
            alertsRaised.clear();
        }
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
