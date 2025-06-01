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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.longThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.internal.matchers.GreaterThan;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.utils.Pair;

class RateLimiterUnitTest {
    RateLimitOptions params;

    /** Domain group by rule. */
    RateLimitRule ruleExampleDotCom;

    /** Host. */
    RateLimitRule ruleWwwOwaspDotCom;

    /** Domain group by host. */
    RateLimitRule ruleSubBigcorpDotCom;

    /** More specific bigcorp.com. */
    RateLimitRule ruleCareersBigcorpDotCom;

    /** Always disabled. */
    RateLimitRule ruleDisabled;

    RateLimiter.Observer observer1;
    RateLimiterImpl.WaitAction wait;

    @BeforeEach
    void setUp() {
        ruleExampleDotCom =
                new RateLimitRule(
                        "example.com", "example.com", false, 30, RateLimitRule.GroupBy.RULE, true);

        ruleWwwOwaspDotCom =
                new RateLimitRule(
                        "www.owasp.com",
                        "www.owasp.com",
                        false,
                        12,
                        RateLimitRule.GroupBy.HOST,
                        true);

        ruleSubBigcorpDotCom =
                new RateLimitRule(
                        "bigcorp.com", "bigcorp.com", false, 10, RateLimitRule.GroupBy.HOST, true);

        ruleCareersBigcorpDotCom =
                new RateLimitRule(
                        "careers.bigcorp.com",
                        "careers.bigcorp.com",
                        false,
                        1,
                        RateLimitRule.GroupBy.HOST,
                        true);

        ruleDisabled =
                new RateLimitRule(
                        "nowhere.com", "nowhere.com", false, 15, RateLimitRule.GroupBy.HOST, false);

        params = new RateLimitOptions();
        params.addRule(ruleExampleDotCom);
        params.addRule(ruleWwwOwaspDotCom);
        params.addRule(ruleSubBigcorpDotCom);
        params.addRule(ruleCareersBigcorpDotCom);
        params.addRule(ruleDisabled);

        observer1 = Mockito.mock(RateLimiter.Observer.class);
        wait = Mockito.mock(RateLimiterImpl.WaitAction.class);
    }

    private static HttpMessage msg(String host) throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://" + host + "/ HTTP/1.0");
        return msg;
    }

    @Test
    void shouldNotChangeTrackedEntriesWhenConfigChangeIsCalledWithNoChange()
            throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        limiter.getOrCreate(msg("www.example.com"), 0);
        limiter.getOrCreate(msg("www.owasp.com"), 0);
        limiter.getOrCreate(msg("www.bigcorp.com"), 0);
        // Then
        List<RateLimiterEntry> entries = limiter.getEntries();
        assertThat(entries.size(), equalTo(3));
        // When
        limiter.configChange(params);
        // Then
        assertThat(limiter.getEntries(), equalTo(entries));
    }

    @Test
    void shouldRemoveTrackedEntryForDisabledRuleOnConfigChanged()
            throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        limiter.getOrCreate(msg("www.example.com"), 0);
        limiter.getOrCreate(msg("www.owasp.com"), 0);
        limiter.getOrCreate(msg("www.bigcorp.com"), 0);
        // Then
        assertThat(limiter.getEntries().size(), equalTo(3));
        // When
        ruleWwwOwaspDotCom.setEnabled(false);
        limiter.configChange(params);
        // Then
        assertThat(limiter.getEntries().size(), equalTo(2));
    }

    @Test
    void shouldReturnSameObjectForRepeatedCallsToGetOrCreate() throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        Pair<RateLimiterEntry, RateLimitRule> example1 = limiter.getOrCreate(msg("example.com"), 0);
        Pair<RateLimiterEntry, RateLimitRule> example2 =
                limiter.getOrCreate(msg("www.example.com"), 0);
        Pair<RateLimiterEntry, RateLimitRule> example3 =
                limiter.getOrCreate(msg("ww2.example.com"), 0);
        Pair<RateLimiterEntry, RateLimitRule> owasp1 = limiter.getOrCreate(msg("www.owasp.com"), 0);
        Pair<RateLimiterEntry, RateLimitRule> nomatch =
                limiter.getOrCreate(msg("www.nomatch.com"), 0);

        // Then
        assertThat(example1.first, sameInstance(example2.first));
        assertThat(example1.first, sameInstance(example3.first));
        assertThat(example1.second, equalTo(ruleExampleDotCom));
        assertThat(example2.second, equalTo(ruleExampleDotCom));
        assertThat(example3.second, equalTo(ruleExampleDotCom));

        assertThat(owasp1.first, not(sameInstance(example1.first)));
        assertThat(owasp1.second, equalTo(ruleWwwOwaspDotCom));

        assertThat(nomatch, nullValue());
    }

    @Test
    void shouldCreateMultipleLimiterEntriesForDomainRuleGroupedByHost()
            throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        for (String host :
                new String[] {
                    "owasp.com",
                    "www.owasp.com",
                    "www.bigcorp.com",
                    "www2.bigcorp.com",
                    "www3.bigcorp.com"
                }) {
            limiter.getOrCreate(msg(host), 0);
            limiter.getOrCreate(msg(host), 0);
        }
        // Then
        List<RateLimiterEntry> entries = limiter.getEntries();
        assertThat(entries.size(), equalTo(4));
        List<String> keys =
                entries.stream()
                        .map(e -> e.getKey().getRuleDescription() + ":" + e.getKey().getKey())
                        .sorted()
                        .collect(Collectors.toList());
        assertThat(
                keys,
                equalTo(
                        List.of(
                                "bigcorp.com:www.bigcorp.com",
                                "bigcorp.com:www2.bigcorp.com",
                                "bigcorp.com:www3.bigcorp.com",
                                "www.owasp.com:www.owasp.com")));
    }

    @Test
    void shouldCreateSingleLimiterEntriesForDomainRuleGroupedByRule()
            throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        for (String host :
                new String[] {
                    "example.com", "www.example.com", "www2.example.com", "www3.example.com"
                }) {
            limiter.getOrCreate(msg(host), 0);
            limiter.getOrCreate(msg(host), 0);
        }
        // Then
        List<RateLimiterEntry> entries = limiter.getEntries();
        assertThat(entries.size(), equalTo(1));
        List<String> keys =
                entries.stream()
                        .map(e -> e.getKey().getRuleDescription() + ":" + e.getKey().getKey())
                        .sorted()
                        .collect(Collectors.toList());
        assertThat(keys, equalTo(List.of("example.com:example.com")));
    }

    @Test
    void shouldUseMostLimitingRuleWhenMultipleRulesMatch() throws HttpMalformedHeaderException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When
        limiter.configChange(params);
        Pair<RateLimiterEntry, RateLimitRule> big1 = limiter.getOrCreate(msg("www.bigcorp.com"), 0);
        Pair<RateLimiterEntry, RateLimitRule> big2 =
                limiter.getOrCreate(msg("careers.bigcorp.com"), 0);
        // Then
        assertThat(big1.first, not(sameInstance(big2.first)));
        assertThat(big1.second, equalTo(ruleSubBigcorpDotCom));
        assertThat(big2.second, equalTo(ruleCareersBigcorpDotCom));
    }

    @Test
    void throttleNoRules() throws IOException, InterruptedException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setWait(wait);
        HttpMessage msg = msg("www.example.com");
        // When
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        // Then
        verify(wait, times(0)).waitFor(anyLong());
    }

    @Test
    void throttleFirstRequest() throws IOException, InterruptedException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setWait(wait);
        limiter.configChange(params);
        HttpMessage msg = msg("www.example.com");
        // When
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        // Then
        verify(wait, times(0)).waitFor(anyLong());
    }

    @Test
    void throttleSecondRequestThrottled() throws IOException, InterruptedException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setWait(wait);
        limiter.configChange(params);
        HttpMessage msg = msg("www.example.com");
        // When
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        // Then
        verify(wait).waitFor(longThat(new GreaterThan<>(0L)));
    }

    @Test
    void throttleSecondRequestNotThrottled() throws IOException, InterruptedException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setWait(wait);
        limiter.configChange(params);
        HttpMessage msg = msg("www.example.com");
        // When
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        Thread.sleep(1000);
        limiter.throttle(msg, HttpSender.MANUAL_REQUEST_INITIATOR);
        // Then
        verify(wait, times(0)).waitFor(anyLong());
    }

    @Test
    void throttleDifferentDomainsNotThrottled() throws IOException, InterruptedException {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setWait(wait);
        limiter.configChange(params);
        HttpMessage msg1 = msg("www.example.com");
        HttpMessage msg2 = msg("www.owasp.com");
        HttpMessage msg3 = msg("www.smallcorp.com");
        // When
        limiter.throttle(msg1, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg2, HttpSender.MANUAL_REQUEST_INITIATOR);
        limiter.throttle(msg3, HttpSender.MANUAL_REQUEST_INITIATOR);
        // Then
        verify(wait, times(0)).waitFor(anyLong());
    }

    @Test
    void setObserver() {
        // Given
        RateLimiterImpl limiter = new RateLimiterImpl();
        // When: observer is set
        limiter.setObserver(observer1);
        // Then: observer receives event
        verify(observer1).limiterUpdated(any());
    }

    @Test
    void setObserverNull() {
        // Given: existing observer is set
        RateLimiterImpl limiter = new RateLimiterImpl();
        limiter.setObserver(observer1);
        // When: null observer is set
        limiter.setObserver(null);
        // Then: no exception is thrown
        // Then: existing observer does not receive any other event
        verify(observer1).limiterUpdated(any());
    }
}
