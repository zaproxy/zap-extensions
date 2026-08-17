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

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.ExtensionAscanRules;
import org.zaproxy.zap.extension.ascanrules.sqli.SqlInjectionModularScanRule;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Integration test for {@link BooleanBasedDetectionStrategy}, exercised through the full {@link
 * SqlInjectionModularScanRule} orchestrator against a real (embedded) HTTP server.
 */
class BooleanBasedDetectionStrategyUnitTest
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
    void shouldAlertWhenBooleanConditionControlsResponse() throws Exception {
        // Given
        String path = "/sqli/boolean/injectable/";
        nano.addHandler(new BooleanInjectableHandler(path, "id"));
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("id")));
    }

    @Test
    void shouldNotAlertWhenResponseIsAlwaysTheSame() throws Exception {
        // Given: not injectable -- the page ignores the parameter entirely, so true/false/baseline
        // are all identical and there's no differential to detect.
        String path = "/sqli/boolean/static/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("Always the same content, id ignored");
                    }
                });
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }

    /**
     * Simulates a page vulnerable to boolean-based blind SQLi: a true condition reproduces the
     * baseline content, a false condition returns different (empty) content, anything else is
     * treated like the baseline.
     */
    private static class BooleanInjectableHandler extends NanoServerHandler {

        private final String param;

        BooleanInjectableHandler(String path, String param) {
            super(path);
            this.param = param;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            // Note: deliberately does NOT reflect the raw parameter value into the body -- real
            // vulnerable pages return the same row content regardless of the exact injected
            // string, and reflecting it back here would make ComparableResponse see every
            // response as different just because the payload text differs.
            String value = getFirstParamValue(session, param);
            if (value != null && (value.contains("'1'='2'") || value.contains("1=2"))) {
                return newFixedLengthResponse("");
            }
            return newFixedLengthResponse("Some Content, matching row found");
        }
    }
}
