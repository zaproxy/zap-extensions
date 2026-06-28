/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
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
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit tests for {@link JwtScanRule}. */
class JwtScanRuleUnitTest extends ActiveScannerTest<JwtScanRule> {

    // JWT: header={"alg":"HS256","typ":"JWT"}, payload={"sub":"user123"}
    private static final String VALID_JWT =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiJ1c2VyMTIzIn0"
                    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    // getHttpMessage() populates the response with this body and HTTP 200
    private static final String DEFAULT_RESPONSE_BODY = "<html></html>";

    @Override
    protected JwtScanRule createScanner() {
        return new JwtScanRule();
    }

    // --- Metadata ---

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int id = rule.getId();
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        int risk = rule.getRisk();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(id, is(equalTo(JwtScanRule.PLUGIN_ID)));
        assertThat(cwe, is(equalTo(347)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(risk, is(equalTo(Alert.RISK_HIGH)));
        assertThat(tags.isEmpty(), is(false));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A04_CRYPTO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A07_AUTH_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A07_AUTH_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_01_SESS_MANAGEMENT.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
    }

    @Test
    void shouldProvideExampleAlerts() {
        // When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        assertThat(alerts.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alerts.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    // --- JWT detection ---

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Standard HS256 JWT
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.sig",
                // RS256 JWT
                "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.bG9uZ3NpZ25hdHVyZQ"
            })
    void shouldDetectValidJwts(String token) {
        assertThat(JwtScanRule.looksLikeJwt(token), is(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"notAToken", "abc.def", "abc.def.ghi", "", "Bearer token"})
    void shouldNotDetectNonJwtStrings(String value) {
        assertThat(JwtScanRule.looksLikeJwt(value), is(false));
    }

    @Test
    void shouldFindJwtInAuthorizationHeader() throws Exception {
        // Given
        HttpMessage msg = getHttpMessage("/secure");
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + VALID_JWT);
        // When
        List<JwtScanRule.JwtLocation> tokens = rule.findJwts(msg);
        // Then
        assertThat(tokens, hasSize(1));
        assertThat(tokens.get(0).source, is(JwtScanRule.JwtLocation.Source.HEADER));
        assertThat(tokens.get(0).name, is(equalTo("Authorization")));
        assertThat(tokens.get(0).token, is(equalTo(VALID_JWT)));
    }

    @Test
    void shouldFindJwtInCookie() throws Exception {
        // Given
        HttpMessage msg = getHttpMessage("/secure");
        msg.getRequestHeader().setHeader("Cookie", "session=" + VALID_JWT);
        // When
        List<JwtScanRule.JwtLocation> tokens = rule.findJwts(msg);
        // Then
        assertThat(tokens, hasSize(1));
        assertThat(tokens.get(0).source, is(JwtScanRule.JwtLocation.Source.COOKIE));
        assertThat(tokens.get(0).name, is(equalTo("session")));
    }

    @Test
    void shouldFindNoTokensWhenNonePresent() throws Exception {
        // Given
        HttpMessage msg = getHttpMessage("/public");
        // When
        List<JwtScanRule.JwtLocation> tokens = rule.findJwts(msg);
        // Then
        assertThat(tokens, is(empty()));
    }

    // --- Scan behaviour ---

    @Test
    void shouldNotScanWhenNoJwtInRequest() throws Exception {
        // Given – request without any JWT
        HttpMessage msg = getHttpMessage("/public");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then – no attack requests sent
        assertThat(alertsRaised, is(empty()));
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldNotScanWhenOriginalResponseIsNotSuccessful() throws Exception {
        // Given – original response is 401 (e.g. expired token, won't be scanned)
        HttpMessage msg = getHttpMessage("/protected");
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + VALID_JWT);
        msg.getResponseHeader().setStatusCode(401);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then – skip non-2xx original responses
        assertThat(alertsRaised, is(empty()));
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldRaiseAlertWhenServerAcceptsNoneAlgToken() throws Exception {
        // Given – vulnerable server: accepts any JWT regardless of algorithm
        String path = "/vulnerable";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        // Return same body for all requests (including "none" alg attack)
                        return newFixedLengthResponse(DEFAULT_RESPONSE_BODY);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + VALID_JWT);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getParam(), is(equalTo("Authorization")));
        assertThat(alert.getAlertRef(), is(equalTo(JwtScanRule.PLUGIN_ID + "-1")));
    }

    @Test
    void shouldNotRaiseAlertWhenServerRejectsNoneAlgToken() throws Exception {
        // Given – correctly configured server: rejects "none" algorithm JWTs
        String path = "/secure-endpoint";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String auth = session.getHeaders().getOrDefault("authorization", "");
                        // A correct server rejects JWTs with empty signatures ("none" alg)
                        if (auth.endsWith(".")) {
                            return newFixedLengthResponse(
                                    Response.Status.UNAUTHORIZED,
                                    NanoHTTPD.MIME_HTML,
                                    "<html><body>Unauthorized</body></html>");
                        }
                        return newFixedLengthResponse(DEFAULT_RESPONSE_BODY);
                    }
                });
        HttpMessage msg = getHttpMessage(path);
        msg.getRequestHeader().setHeader("Authorization", "Bearer " + VALID_JWT);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    // --- Utility methods ---

    @Test
    void shouldRoundTripBase64UrlEncoding() {
        String original = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String encoded = JwtScanRule.encodeBase64Url(original);
        String decoded = JwtScanRule.decodeBase64Url(encoded);
        assertThat(decoded, is(equalTo(original)));
    }

    @Test
    void shouldDecodeKnownBase64UrlValue() {
        // Known JWT header: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 → {"alg":"HS256","typ":"JWT"}
        String decoded = JwtScanRule.decodeBase64Url("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        assertThat(decoded, is(equalTo("{\"alg\":\"HS256\",\"typ\":\"JWT\"}")));
    }
}
