/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ratelimit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RateLimitOptionsUnitTest {
    RateLimitOptions param;

    @BeforeEach
    void setUp() {
        param = new RateLimitOptions();
    }

    @Test
    void shouldIgnoreAddingDuplicateRules() {
        // Given
        RateLimitRule rule1 =
                new RateLimitRule(
                        "example.com", "example.com", false, 10, RateLimitRule.GroupBy.RULE, true);
        RateLimitRule rule2 =
                new RateLimitRule(
                        "example.com", "example.com", false, 20, RateLimitRule.GroupBy.RULE, true);
        RateLimitRule rule3 =
                new RateLimitRule(
                        "example.com",
                        "^\\Qexample.com\\E$",
                        true,
                        25,
                        RateLimitRule.GroupBy.RULE,
                        true);
        RateLimitRule rule4 =
                new RateLimitRule(
                        "example.com2", "example.com", false, 30, RateLimitRule.GroupBy.RULE, true);
        RateLimitRule rule5 =
                new RateLimitRule(
                        "example.co.uk",
                        "example.co.uk",
                        false,
                        40,
                        RateLimitRule.GroupBy.RULE,
                        true);

        // When
        param.addRule(rule1);
        param.addRule(rule2);
        param.addRule(rule3);
        param.addRule(rule4);
        param.addRule(rule5);

        // Then
        assertThat(param.getRules().size(), equalTo(2));
        assertThat(param.getRules().contains(rule1), equalTo(true));
        assertThat(param.getRules().contains(rule2), equalTo(false));
        assertThat(param.getRules().contains(rule3), equalTo(false));
        assertThat(param.getRules().contains(rule4), equalTo(false));
        assertThat(param.getRules().contains(rule5), equalTo(true));
    }
}
