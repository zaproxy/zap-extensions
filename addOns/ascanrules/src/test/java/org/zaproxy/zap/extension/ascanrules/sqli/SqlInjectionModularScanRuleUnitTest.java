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
package org.zaproxy.zap.extension.ascanrules.sqli;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.ascanrules.ExtensionAscanRules;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

/**
 * Unit test for {@link SqlInjectionModularScanRule} itself -- id/metadata wiring and the
 * orchestrator's own behavior (stop-at-first-alert, safe with no matching strategy). Each
 * individual {@link DetectionStrategy} has its own dedicated test alongside its implementation
 * (e.g. {@code strategies/ErrorBasedDetectionStrategyUnitTest}).
 */
class SqlInjectionModularScanRuleUnitTest
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
    void shouldHaveExpectedId() {
        assertThat(rule.getId(), is(equalTo(424242)));
    }

    @Test
    void shouldHaveNonEmptyMetadata() {
        assertThat(rule.getName(), is(not(emptyOrNullString())));
        assertThat(rule.getDescription(), is(not(emptyOrNullString())));
        assertThat(rule.getSolution(), is(not(emptyOrNullString())));
        assertThat(rule.getCweId(), is(equalTo(89)));
        assertThat(rule.getWascId(), is(equalTo(19)));
    }

    @Test
    void shouldRaiseNoAlertsWhenNoStrategyMatches() throws Exception {
        // Given
        String path = "/sqli/scaffold/";
        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse("ok");
                    }
                });
        rule.init(getHttpMessage(path + "?id=1"), parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, is(empty()));
    }
}
