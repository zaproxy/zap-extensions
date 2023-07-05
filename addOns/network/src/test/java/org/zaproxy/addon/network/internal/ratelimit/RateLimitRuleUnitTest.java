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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;

class RateLimitRuleUnitTest {

    private static RateLimitRule newRule(String matchString, boolean matchRegex) {
        return new RateLimitRule(
                "test", matchString, matchRegex, 1, RateLimitRule.GroupBy.RULE, true);
    }

    @Test
    void shouldMatchStandardDotComHostsUsingStringMatcher() throws URIException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("https://www.example.com/", false));
        // When-Then
        assertThat(newRule("example.com", false).matches(msg), equalTo(true));
        assertThat(newRule("www.example.com", false).matches(msg), equalTo(true));
        assertThat(newRule("www2.example.com", false).matches(msg), equalTo(false));
    }

    @Test
    void shouldMatchStandardDotComHostsUsingRegex() throws URIException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("https://www.example.com/", false));
        // When-Then
        assertThat(newRule("^\\Qexample.com\\E$", true).matches(msg), equalTo(false));
        assertThat(newRule("^([\\w.]+[.])?\\Qexample.com\\E$", true).matches(msg), equalTo(true));
    }

    @Test
    void shouldStringMatchIP4Address() throws URIException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://192.168.1.1/", false));
        // When-Then
        assertThat(newRule("192.168.1.1", false).matches(msg), equalTo(true));
        assertThat(newRule("192.168.1.2", false).matches(msg), equalTo(false));
        assertThat(newRule("1.1", false).matches(msg), equalTo(false));
        assertThat(newRule("www.example.com", false).matches(msg), equalTo(false));
    }

    @Test
    void shouldStringMatchIP6LocalHost() throws URIException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://[::1]/", false));
        // When-Then
        assertThat(newRule("[::1]", false).matches(msg), equalTo(true));
        assertThat(newRule("[::2]", false).matches(msg), equalTo(false));
        assertThat(newRule("www.example.com", false).matches(msg), equalTo(false));
    }

    @Test
    void shouldStringMatchIP6Address() throws URIException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setURI(new URI("http://[fe80::456:8bf5:894f:87c6]/", false));
        // When-Then
        assertThat(newRule("[fe80::456:8bf5:894f:87c6]", false).matches(msg), equalTo(true));
        assertThat(newRule("[::1]", false).matches(msg), equalTo(false));
        assertThat(newRule("www.example.com", false).matches(msg), equalTo(false));
    }
}
