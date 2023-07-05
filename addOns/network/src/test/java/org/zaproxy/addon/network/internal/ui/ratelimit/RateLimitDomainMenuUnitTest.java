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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;

class RateLimitDomainMenuUnitTest {
    private HttpMessage msg;
    private RateLimitDomainMenu menu;

    @BeforeEach
    void setUp() {
        msg = new HttpMessage();

        menu = new RateLimitDomainMenu(null, "test");
    }

    @ParameterizedTest
    @ValueSource(strings = {"www.example.com", "example.com", "one.www.example.com"})
    void shouldAddDomainRuleForStandardDotComHosts(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo("example.com"));
        assertThat(rule.getMatchString(), equalTo("example.com"));
        assertCommonProperties(rule);
    }

    private static void assertCommonProperties(RateLimitRule rule) {
        assertThat(rule.isMatchRegex(), equalTo(false));
        assertThat(rule.getRequestsPerSecond(), equalTo(1));
        assertThat(rule.getGroupBy(), equalTo(RateLimitRule.GroupBy.RULE));
        assertThat(rule.isEnabled(), equalTo(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {"www.example.co.uk", "example.co.uk", "one.www.example.co.uk"})
    void shouldAddDomainRuleForCountrySpecificDotComHosts(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo("example.co.uk"));
        assertThat(rule.getMatchString(), equalTo("example.co.uk"));
        assertCommonProperties(rule);
    }

    @Test
    void shouldAddDomainRuleForStandardDotNetHosts() throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://testfire.net/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo("testfire.net"));
        assertThat(rule.getMatchString(), equalTo("testfire.net"));
        assertCommonProperties(rule);
    }

    @ParameterizedTest
    @ValueSource(strings = {"crash.sh", "www.crash.sh"})
    void shouldAddDomainRuleForTwoCharacterTLD(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo("crash.sh"));
        assertThat(rule.getMatchString(), equalTo("crash.sh"));
        assertCommonProperties(rule);
    }

    @Test
    void shouldAddDomainRuleForLongTLD() throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://www.thehacker.receipes/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo("thehacker.receipes"));
        assertThat(rule.getMatchString(), equalTo("thehacker.receipes"));
        assertCommonProperties(rule);
    }

    @ParameterizedTest
    @ValueSource(strings = {"192.168.1.1", "[::1]", "[fe80::456:8bf5:894f:87c6]"})
    void shouldRecognizeIPAddressWhenAddingAsADomain(String host) throws URIException {
        // Given
        msg.getRequestHeader().setURI(new URI("http://" + host + "/", false));
        // When
        RateLimitRule rule = menu.createRule(msg);
        // Then
        assertThat(rule.getDescription(), equalTo(host));
        assertThat(rule.getMatchString(), equalTo(host));
        assertCommonProperties(rule);
    }
}
