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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link ForbiddenBypassScanRule}. */
public class ForbiddenBypassScanRuleUnitTest extends ActiveScannerTest<ForbiddenBypassScanRule> {

    private static final String PROTECTED_PATH = "/protected/endpoint";

    private static final String GENERIC_RESPONSE =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body></body></html>";

    @Override
    protected ForbiddenBypassScanRule createScanner() {
        return new ForbiddenBypassScanRule();
    }

    @Test
    public void shouldNotAlertIfInitialRequestIsNotForbidden() throws Exception {
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
    public void shouldNotAlertIfAllRequestsAreForbidden() throws Exception {
        // Given
        String path = "/forbidden/";
        nano.addHandler(new ForbiddenResponse(path));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(23, httpMessagesSent.size());
    }

    @Test
    public void shouldAlertIfOkObtained() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new OkResponse("/." + PROTECTED_PATH)); // Period is %2e
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("/%2e" + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    public void shouldAlertIfOkWithRewriteUrlHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/anything", "x-rewrite-url"));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("X-Rewrite-URL: " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    public void shouldAlertIfOkWithRefererHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/anything", "referer"));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("Referer: " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    public void shouldAlertIfOkWithOriginalUrlHeader() throws Exception {
        // Given
        nano.addHandler(new ForbiddenResponse(PROTECTED_PATH));
        nano.addHandler(new ResponseWithHeaderPayload("/", "x-original-url"));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("X-Original-URL: " + PROTECTED_PATH, alert.getAttack());
        assertAlert(alert);
    }

    @Test
    public void shouldAlertIfOkWithCustomIpAuthorizationHeader() throws Exception {
        // Given
        nano.addHandler(new ResponseWithHeaderPayload(PROTECTED_PATH, "x-custom-ip-authorization"));
        HttpMessage msg = this.getHttpMessage(PROTECTED_PATH);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals("X-Custom-IP-Authorization: 127.0.0.1", alert.getAttack());
        assertAlert(alert);
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
