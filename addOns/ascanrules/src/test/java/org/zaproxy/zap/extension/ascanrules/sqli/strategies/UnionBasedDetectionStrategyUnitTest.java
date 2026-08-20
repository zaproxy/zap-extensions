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
import static org.hamcrest.Matchers.hasSize;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.ExtensionAscanRules;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Integration test for {@link UnionBasedDetectionStrategy} based on WAVSEP test case:
 * SQL-Injection/SInjection-Detection-Evaluation-GET-200Error/Case02-InjectionInSearch-String-UnionExploit-With200Errors.jsp
 *
 * <p>Tests UNION-based SQL injection in a LIKE clause where:
 * - Normal query: SELECT msgid, title, message FROM messages WHERE message like'<input>%'
 * - UNION attack: message like'' UNION ALL SELECT ... -- %'
 * - Expected response: Either UNION error signature or different data (3 columns expected)
 */
class UnionBasedDetectionStrategyUnitTest
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
    void shouldAlertOnUnionBasedInjectionInLikeClause() throws Exception {
        // WAVSEP Case02: UNION-based SQLi in a LIKE clause with 200 Error responses
        String path = "/sqli/union/search/";
        nano.addHandler(new UnionInjectableHandler(path, "msg"));
        rule.init(getHttpMessage(path + "?msg=test"), parent);

        rule.scan();

        assertThat(
                "Should detect UNION-based injection in LIKE clause",
                alertsRaised,
                hasSize(1));
    }

    @Test
    void shouldNotAlertOnNormalSearchQuery() throws Exception {
        String path = "/sqli/union/search/";
        nano.addHandler(new UnionInjectableHandler(path, "msg"));
        rule.init(getHttpMessage(path + "?msg=hello"), parent);

        rule.scan();

        // Normal query should not trigger alert
        assertThat(alertsRaised, empty());
    }

    /**
     * Simulates WAVSEP Case02: vulnerable LIKE clause that accepts UNION payloads.
     *
     * <p>Vulnerable SQL: SELECT msgid, title, message FROM messages WHERE message like'<input>%'
     *
     * <p>When input='UNION ALL SELECT 1,2,3 --, the query becomes:
     * SELECT msgid, title, message FROM messages WHERE message like''UNION ALL SELECT 1,2,3 -- %'
     *
     * <p>Expected: Either UNION-specific error (column mismatch) or different result set with 3 columns.
     */
    private static class UnionInjectableHandler extends NanoServerHandler {
        private final String param;

        UnionInjectableHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value == null || value.isEmpty()) {
                return newFixedLengthResponse(normalResponse());
            }

            // Check if UNION payload is present
            if (value.contains("UNION") || value.contains("union")) {
                // UNION payload detected — return either:
                // 1. UNION-specific error (MySQL: "different number of columns")
                // 2. Different data structure (e.g., 3-column output instead of search results)
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK,
                        NanoHTTPD.MIME_HTML,
                        "ERROR: The used SELECT statements have a different number of columns");
            }

            // Non-UNION injection attempts (error-based, boolean-based) should get normal or error response
            if (value.contains("'") || value.contains("\"")) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.OK,
                        NanoHTTPD.MIME_HTML,
                        "ERROR in SQL syntax near '" + value + "'");
            }

            return newFixedLengthResponse(normalResponse());
        }

        private String normalResponse() {
            return "<html><body><table>"
                    + "<tr><td>1</td><td>Title1</td><td>Message1</td></tr>"
                    + "<tr><td>2</td><td>Title2</td><td>Message2</td></tr>"
                    + "</table></body></html>";
        }
    }
}
