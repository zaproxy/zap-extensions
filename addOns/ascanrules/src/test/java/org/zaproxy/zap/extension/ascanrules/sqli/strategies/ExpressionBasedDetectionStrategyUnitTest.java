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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
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
 * Integration test for {@link ExpressionBasedDetectionStrategy}, exercised through the full
 * {@link SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server.
 */
class ExpressionBasedDetectionStrategyUnitTest
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
    void shouldAlertWhenExpressionIsEvaluated() throws Exception {
        String path = "/sqli/expression/injectable/";
        nano.addHandler(new ExpressionEvaluatingHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        rule.scan();

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertWhenExpressionIsNotEvaluated() throws Exception {
        String path = "/sqli/expression/safe/";
        nano.addHandler(new NonExpressionEvaluatingHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        rule.scan();

        assertThat(alertsRaised, is(empty()));
    }

    /**
     * Handler that evaluates numeric expressions. For example, if id=1, id=3-2, and id=2-1 all
     * return the same content, but id=4-2 returns different content, this suggests SQL injection.
     */
    private static class ExpressionEvaluatingHandler extends NanoServerHandler {
        private final String param;

        ExpressionEvaluatingHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value == null) {
                value = "";
            }

            // Try to evaluate as expression
            try {
                int result = evaluateExpression(value);
                if (result == 1) {
                    return NanoHTTPD.newFixedLengthResponse(
                            "User ID: " + result + ", Data: Secret Info");
                } else {
                    return NanoHTTPD.newFixedLengthResponse("User ID: " + result + ", Data: ");
                }
            } catch (Exception e) {
                return NanoHTTPD.newFixedLengthResponse("Error processing: " + value);
            }
        }

        private int evaluateExpression(String expr) throws Exception {
            // Simple expression evaluator for testing
            if (expr.contains("+")) {
                String[] parts = expr.split("\\+");
                return Integer.parseInt(parts[0].trim()) + Integer.parseInt(parts[1].trim());
            } else if (expr.contains("-")) {
                String[] parts = expr.split("-");
                if (parts.length == 2) {
                    return Integer.parseInt(parts[0].trim()) - Integer.parseInt(parts[1].trim());
                }
            } else if (expr.contains("/")) {
                String[] parts = expr.split("/");
                return Integer.parseInt(parts[0].trim()) / Integer.parseInt(parts[1].trim());
            }
            return Integer.parseInt(expr);
        }
    }

    /** Handler that doesn't evaluate expressions - just returns the same content for all values. */
    private static class NonExpressionEvaluatingHandler extends NanoServerHandler {
        private final String param;

        NonExpressionEvaluatingHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            // Always return the same content, ignoring the parameter
            return NanoHTTPD.newFixedLengthResponse("User ID: 1, Data: Secret Info");
        }
    }
}
