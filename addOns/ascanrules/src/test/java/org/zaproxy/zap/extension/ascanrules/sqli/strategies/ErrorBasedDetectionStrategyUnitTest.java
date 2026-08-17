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
package org.zaproxy.zap.extension.ascanrules.sqli.strategies;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.ExtensionAscanRules;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Integration test for {@link ErrorBasedDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server, matching the
 * repo's existing NanoHTTPD-based scan rule test convention.
 */
class ErrorBasedDetectionStrategyUnitTest
        extends ActiveScannerTestUtils<SqlInjectionModularScanRule> {

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRules());
    }

    @Override
    protected SqlInjectionModularScanRule createScanner() {
        return new SqlInjectionModularScanRule();
    }

    @Test
    void shouldAlertWhenSqlMetacharacterTriggersRealDbError() throws Exception {
        // Given
        String path = "/sqli/error/genuine/";
        nano.addHandler(new GenuineSqlErrorHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("id")));
    }

    @Test
    void shouldNotAlertWhenPageErrorsOnAnyMalformedInput() throws Exception {
        // Given: a WAVSEP-style honeypot -- it returns a SQL-error-shaped response for ANY
        // value other than the exact expected one, not specifically because of SQL
        // metacharacters. A naive error-signature match (with no control-value re-check) would
        // false-positive on this.
        String path = "/sqli/error/honeypot/";
        nano.addHandler(new HoneypotHandler(path, "id", "1"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldNotAlertOnOrdinaryPage() throws Exception {
        // Given
        String path = "/sqli/error/none/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("Some ordinary content");
                    }
                });
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /** Errors with a MySQL-shaped message only when the parameter contains a SQL metacharacter. */
    private static class GenuineSqlErrorHandler extends NanoServerHandler {

        private final String param;

        GenuineSqlErrorHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value != null && (value.contains("'") || value.contains("\""))) {
                return newFixedLengthResponse(
                        Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_HTML,
                        "Warning: You have an error in your SQL syntax near '" + value + "'");
            }
            return newFixedLengthResponse("Some ordinary content for " + value);
        }
    }

    /** Errors with a MySQL-shaped message for any value that isn't exactly the expected one. */
    private static class HoneypotHandler extends NanoServerHandler {

        private final String param;
        private final String expectedValue;

        HoneypotHandler(String path, String param, String expectedValue) {
            super(path);
            this.param = param;
            this.expectedValue = expectedValue;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (expectedValue.equals(value)) {
                return newFixedLengthResponse("Some ordinary content for " + value);
            }
            return newFixedLengthResponse(
                    Response.Status.INTERNAL_ERROR,
                    NanoHTTPD.MIME_HTML,
                    "Warning: You have an error in your SQL syntax near '" + value + "'");
        }
    }
}
