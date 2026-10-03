/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ForbiddenBypassScanRule}. */
class ForbiddenBypassScanRuleUnitTest extends ActiveScannerTest<ForbiddenBypassScanRule> {

    private static final String PROTECTED_PATH = "/protected/endpoint";

    private static final String GENERIC_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body></body></html>";

    @Override
    protected ForbiddenBypassScanRule createScanner() {
        return new ForbiddenBypassScanRule();
    }

    private static Stream<Arguments> createTestPatterns() {
        return Stream.of(
                Arguments.of("dot", "/./", "/./"),
                Arguments.of("dot2", "..;/", "..;/"),
                Arguments.of("slash", "/", "/"),
                Arguments.of("testus", "/.testus", "/.testus"),
                Arguments.of("app.py", "../app.py", "../app.py"),
                Arguments.of("blank", " /", "%20/"),
                Arguments.of("tab", "\t/", "%09/"));
    }

    @Test
    void shouldNotAlertIfInitialRequestIsNotForbidden() throws Exception {
        // Given
        String path = "/allowed/";
        nano.addHandler(new OkResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(1, httpMessagesSent.size());
    }

    @Test
    void shouldNotAlertIfAllRequestsAreForbidden() throws Exception {
        // Given
        String path = "/forbidden/";
        nano.addHandler(new ForbiddenResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(greaterThan(20)));
    }

    @ParameterizedTest
    @ValueSource(strings = {GENERIC_RESPONSE, ""})
    void shouldNotAlertIfPathPayloadReturnsSpaFallback(String fallbackBody) throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                PROTECTED_PATH.equals(session.getUri())
                                        ? Response.Status.FORBIDDEN
                                        : Response.Status.OK,
                                "text/html",
                                fallbackBody);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @MethodSource("createIgnoredHeaderPaths")
    void shouldNotAlertIfRoutingHeaderIsIgnored(String publicPath) throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                "/".equals(session.getUri()) || publicPath.equals(session.getUri())
                                        ? Response.Status.OK
                                        : Response.Status.FORBIDDEN,
                                "text/html",
                                GENERIC_RESPONSE);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private static Stream<Arguments> createIgnoredHeaderPaths() {
        return Stream.of(Arguments.of("/"), Arguments.of("/anything"));
    }

    @Test
    void shouldNotAlertIfOnlySiblingBaselineReturnsSpaFallback() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                PROTECTED_PATH.equals(session.getUri())
                                                || "/".equals(session.getUri())
                                        ? Response.Status.FORBIDDEN
                                        : Response.Status.OK,
                                "text/html",
                                GENERIC_RESPONSE);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @EnumSource(
            value = Response.Status.class,
            names = {"FORBIDDEN", "NOT_FOUND", "INTERNAL_ERROR"})
    void shouldAlertWhenOnlyErrorBaselinesHaveMatchingBodies(Response.Status baselineStatus)
            throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                PROTECTED_PATH.equals(session.getUri())
                                        ? Response.Status.FORBIDDEN
                                        : (PROTECTED_PATH + "/").equals(session.getUri())
                                                ? Response.Status.OK
                                                : baselineStatus,
                                "text/html",
                                GENERIC_RESPONSE);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(PROTECTED_PATH + "/", alertsRaised.get(0).getAttack());
    }

    @Test
    void shouldContinueIfIndexBaselineCannotBeFetched() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH + "/./"));
        nano.addHandler(new OkResponse(PROTECTED_PATH + "/"));
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        rule =
                new ForbiddenBypassScanRule() {
                    @Override
                    protected void sendAndReceive(HttpMessage message) throws IOException {
                        if ("/".equals(message.getRequestHeader().getURI().getPath())) {
                            throw new IOException("Baseline connection failed");
                        }
                        super.sendAndReceive(message);
                    }
                };
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(PROTECTED_PATH + "/", alertsRaised.get(0).getAttack());
    }

    @Test
    void shouldAlertOnDistinctPathBypassAfterSpaFallback() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (PROTECTED_PATH.equals(session.getUri())) {
                            return newFixedLengthResponse(
                                    Response.Status.FORBIDDEN, "text/html", "Forbidden");
                        }
                        return newFixedLengthResponse(
                                Response.Status.OK,
                                "text/html",
                                (PROTECTED_PATH + "/").equals(session.getUri())
                                        ? "Protected content"
                                        : GENERIC_RESPONSE);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(PROTECTED_PATH + "/", alertsRaised.get(0).getAttack());
        assertAlert(alertsRaised.get(0));
    }

    @Test
    void shouldAlertOnDistinctHeaderBypassAfterSpaFallback() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (session.getHeaders().containsKey("x-custom-ip-authorization")) {
                            return newFixedLengthResponse(
                                    Response.Status.OK, "text/html", "Protected content");
                        }
                        return newFixedLengthResponse(
                                PROTECTED_PATH.equals(session.getUri())
                                        ? Response.Status.FORBIDDEN
                                        : Response.Status.OK,
                                "text/html",
                                GENERIC_RESPONSE);
                    }
                });
        rule.init(getHttpMessage(PROTECTED_PATH), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals("x-custom-ip-authorization: 127.0.0.1", alertsRaised.get(0).getAttack());
        assertAlert(alertsRaised.get(0));
    }

    @ParameterizedTest
    @MethodSource("createTestPatterns")
    void shouldAlertIfOkObtained(String patternName, String patternValue, String patternAttack)
            throws Exception {
        // Given
        String basePath = "/" + patternName + PROTECTED_PATH;
        if ("slash".equals(patternName)) {
            nano.addHandler(new ForbiddenResponse(basePath + "/./"));
        }
        nano.addHandler(new OkResponse(basePath + patternValue));
        nano.addHandler(new ForbiddenResponse(basePath));
        HttpMessage msg = this.getHttpMessage(basePath);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertAlert(alert);
        assertEquals(basePath + patternAttack, alert.getAttack());
    }

    @Test
    void shouldAlertIfOkWithRewriteUrlHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/anything", HttpFieldsNames.X_REWRITE_URL));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(HttpFieldsNames.X_REWRITE_URL + ": " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    void shouldAlertIfOkWithRefererHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/anything", HttpFieldsNames.REFERER));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(HttpFieldsNames.REFERER + ": " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    void shouldAlertIfOkWithOriginalUrlHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/", HttpFieldsNames.X_ORIGINAL_URL));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(HttpFieldsNames.X_ORIGINAL_URL + ": " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    void shouldAlertIfOkWithCustomIpAuthorizationHeader() throws Exception {
        // Given
        nano.addHandler(new ResponseWithHeaderPayload(PROTECTED_PATH, "x-custom-ip-authorization"));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("x-custom-ip-authorization: 127.0.0.1", alert.getAttack());
        assertAlert(alert);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ATHN_04_AUTH_BYPASS.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ATHN_04_AUTH_BYPASS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ATHN_04_AUTH_BYPASS.getValue())));
    }

    private static void assertAlert(Alert alert) {
        assertEquals("Bypassing 403", alert.getName());
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
    }

    private static class OkResponse extends NanoServerHandler {

        public OkResponse(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(Response.Status.OK, "text/html", GENERIC_RESPONSE);
        }
    }

    private static class ForbiddenResponse extends NanoServerHandler {

        public ForbiddenResponse(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(Response.Status.FORBIDDEN, "text/html", GENERIC_RESPONSE);
        }
    }

    private static class ResponseWithHeaderPayload extends NanoServerHandler {

        private final String header;

        public ResponseWithHeaderPayload(String path, String header) {
            super(path);
            this.header = header;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            if (session.getHeaders().get(header) != null) {
                return newFixedLengthResponse(Response.Status.OK, "text/html", GENERIC_RESPONSE);
            }
            return newFixedLengthResponse(Response.Status.FORBIDDEN, "text/html", GENERIC_RESPONSE);
        }
    }
}
