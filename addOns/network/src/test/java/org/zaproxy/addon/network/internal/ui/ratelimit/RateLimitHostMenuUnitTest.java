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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;

class RateLimitHostMenuUnitTest {
    private HttpMessage msg;
    private RateLimitHostMenu menu;

    @BeforeEach
    void setUp() {
        msg = new HttpMessage();

        menu = new RateLimitHostMenu(null, "test");
    }

    @ParameterizedTest
    @ValueSource(strings = {"www.example.com", "example.com", "one.www.example.com"})
    void shouldAddHostRuleForStandardDotComHosts(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo(host));
        assertThat(rule.getMatchString(), equalTo("^\\Q" + host + "\\E$"));
        assertThat(rule.isMatchRegex(), equalTo(true));
        assertCommonProperties(rule);
    }

    private static void assertCommonProperties(RateLimitRule rule) {
        assertThat(rule.getRequestsPerSecond(), equalTo(1));
        assertThat(rule.getGroupBy(), equalTo(RateLimitRule.GroupBy.HOST));
        assertThat(rule.isEnabled(), equalTo(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.168.1.1", "[::1]", "[fe80::456:8bf5:894f:87c6]"})
    void shouldRecognizeIPAddressWhenAddingAsAHost(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo(host));
        assertThat(rule.getMatchString(), equalTo(host));
        assertThat(rule.isMatchRegex(), equalTo(false));
        assertCommonProperties(rule);
    }
}
