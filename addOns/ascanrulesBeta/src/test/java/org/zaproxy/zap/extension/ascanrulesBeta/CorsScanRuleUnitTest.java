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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link CorsScanRule}. */
class CorsScanRuleUnitTest extends ActiveScannerTest<CorsScanRule> {
    private static final String ACAC = "Access-Control-Allow-Credentials";
    private static final String GENERIC_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body></body></html>";

    @Override
    protected CorsScanRule createScanner() {
        return new CorsScanRule();
    }

    @Test
    void shouldNotAlertIfCorsNotSupported() throws Exception {
        // Given
        nano.addHandler(new CorsResponse(null, false));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertInfoIfAcaoButNotPayloads() throws Exception {
        // Given
        nano.addHandler(new CorsResponse("dummyValue", false));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_INFO, "dummyValue");
    }

    @ParameterizedTest
    @ValueSource(strings = {"REFLECT", "*", "null"})
    void shouldAlertMediumIfAcaoPayloads(String origin) throws Exception {
        // Given
        nano.addHandler(new CorsResponse(origin, false));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_MEDIUM, origin);
    }

    @ParameterizedTest
    @ValueSource(strings = {"REFLECT", "null"})
    void shouldAlertHighIfAcaoAndAcacPayloads(String origin) throws Exception {
        // Given
        nano.addHandler(new CorsResponse(origin, true));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_HIGH, origin);
    }

    @Test
    void shouldAlertMediumIfAcaoWildcardAndAcac() throws Exception {
        // Given
        nano.addHandler(new CorsResponse("*", true));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_MEDIUM, "*");
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 401, 403, 404, 415, 500, 503})
    void shouldAlertLowConfidenceIfErrorStatusCodeWithAcaoAndAcac(int statusCode) throws Exception {
        // Given - With ACAO and ACAC headers that would normally be HIGH risk,
        // error responses should have LOW confidence as exploitability is uncertain
        nano.addHandler(new CorsResponse("REFLECT", true, statusCode));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_HIGH, Alert.CONFIDENCE_LOW, "REFLECT");
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 404, 415})
    void shouldAlertLowConfidenceIfErrorStatusCodeWithWildcardAcao(int statusCode) throws Exception {
        // Given - With wildcard ACAO that would normally be MEDIUM risk,
        // error responses should have LOW confidence as exploitability is uncertain
        nano.addHandler(new CorsResponse("*", false, statusCode));
        HttpMessage msg = this.getHttpMessage("/");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertExpectedAlert(Alert.RISK_MEDIUM, Alert.CONFIDENCE_LOW, "*");
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(942)));
        assertThat(wasc, is(equalTo(14)));
        assertThat(tags.size(), is(equalTo(8)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.SYSTEMIC.getTag()),
                is(equalTo(CommonAlertTag.SYSTEMIC.getValue())));
    }

    private void assertExpectedAlert(int risk, String evidence) {
        assertExpectedAlert(risk, Alert.CONFIDENCE_HIGH, evidence);
    }

    private void assertExpectedAlert(int risk, int confidence, String evidence) {
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(risk, alert.getRisk());
        assertEquals(confidence, alert.getConfidence());
        if (evidence.equals("REFLECT")) {
            assertThat(
                    alert.getEvidence().startsWith("access-control-allow-origin: http://"),
                    is(true));
        } else {
            assertEquals("access-control-allow-origin: " + evidence, alert.getEvidence());
        }
    }

    private static class CorsResponse extends NanoServerHandler {
        private final String acaoBehavior;
        private final boolean isAcac;
        private final Response.Status statusCode;

        public CorsResponse(String acaoBehavior, boolean isAcac) {
            this(acaoBehavior, isAcac, 200);
        }

        public CorsResponse(String acaoBehavior, boolean isAcac, int statusCode) {
            super("/");
            this.acaoBehavior = acaoBehavior;
            this.isAcac = isAcac;
            this.statusCode = Response.Status.lookup(statusCode);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            Response resp = newFixedLengthResponse(statusCode, "text/html", GENERIC_RESPONSE);
            if (acaoBehavior == null) {
                return resp;
            }
            String acaoVal = null;
            if (acaoBehavior.equals("REFLECT")) {
                acaoVal = session.getHeaders().get(HttpFieldsNames.ORIGIN);
            } else {
                acaoVal = acaoBehavior;
            }
            resp.addHeader(HttpFieldsNames.ACCESS_CONTROL_ALLOW_ORIGIN, acaoVal);

            if (isAcac) {
                resp.addHeader(ACAC, "true");
            }

            return resp;
        }
    }
}
