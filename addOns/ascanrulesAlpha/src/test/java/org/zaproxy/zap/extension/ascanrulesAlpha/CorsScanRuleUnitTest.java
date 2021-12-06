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
package org.zaproxy.zap.extension.ascanrulesAlpha;

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
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
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
        assertExpectedAlert(Alert.RISK_INFO);
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
        assertExpectedAlert(Alert.RISK_MEDIUM);
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
        assertExpectedAlert(Alert.RISK_HIGH);
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
        assertExpectedAlert(Alert.RISK_MEDIUM);
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
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CLNT_07_CORS.getValue())));
    }

    private void assertExpectedAlert(int risk) {
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(risk, alert.getRisk());
    }

    private static class CorsResponse extends NanoServerHandler {
        private final String acaoBehavior;
        private final boolean isAcac;

        public CorsResponse(String acaoBehavior, boolean isAcac) {
            super("/");
            this.acaoBehavior = acaoBehavior;
            this.isAcac = isAcac;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            Response resp = newFixedLengthResponse(GENERIC_RESPONSE);
            if (acaoBehavior == null) {
                return resp;
            }
            String acaoVal = null;
            if (acaoBehavior.equals("REFLECT")) {
                acaoVal = session.getHeaders().get(HttpRequestHeader.ORIGIN);
            } else {
                acaoVal = acaoBehavior;
            }
            resp.addHeader(HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN, acaoVal);

            if (isAcac) {
                resp.addHeader(ACAC, "true");
            }

            return resp;
        }
    }
}
