/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.network.internal.client.CloseableHttpSenderImpl;

class RateLimitExtensionHelperUnitTest {
    RateLimitExtensionHelper helper;
    CloseableHttpSenderImpl<?> httpSenderNetwork;
    ExtensionHook extensionHook;
    RateLimitRule enabledRule;
    RateLimitRule enabledRule2;
    RateLimitRule disabledRule;

    @BeforeEach
    void setUp() {
        helper = new RateLimitExtensionHelper();
        httpSenderNetwork = mock(CloseableHttpSenderImpl.class);
        extensionHook = mock(ExtensionHook.class);

        enabledRule =
                new RateLimitRule(
                        "example.com", "example.com", false, 30, RateLimitRule.GroupBy.RULE, true);
        enabledRule2 =
                new RateLimitRule(
                        "example.edu", "example.edu", false, 30, RateLimitRule.GroupBy.RULE, true);
        disabledRule =
                new RateLimitRule(
                        "example.com", "example.com", false, 30, RateLimitRule.GroupBy.RULE, false);
    }

    @Test
    void initialLimiterIsNOP() {
        // Given
        // When
        helper.init(httpSenderNetwork);
        helper.hook(extensionHook);
        // Then
        verify(httpSenderNetwork).setRateLimiter(any(NopRateLimiter.class));
    }

    @Test
    void configChangeWithNoRules() {
        // Given
        helper.init(httpSenderNetwork);
        helper.hook(extensionHook);
        // When
        helper.getRateLimitOptions().fireObserver();
        // Then
        verify(httpSenderNetwork).setRateLimiter(any(NopRateLimiter.class));
    }

    @Test
    void configChangeWithNoEnabledRules() {
        // Given
        helper.init(httpSenderNetwork);
        helper.hook(extensionHook);
        // When
        helper.getRateLimitOptions().addRule(disabledRule);
        // Then
        verify(httpSenderNetwork).setRateLimiter(any(NopRateLimiter.class));
    }

    @Test
    void configChangeWithEnabledRule() {
        // Given
        helper.init(httpSenderNetwork);
        helper.hook(extensionHook);
        // When
        helper.getRateLimitOptions().addRule(enabledRule);
        // Then
        verify(httpSenderNetwork).setRateLimiter(any(NopRateLimiter.class));
        verify(httpSenderNetwork).setRateLimiter(any(RateLimiterImpl.class));
    }

    @Test
    void configChangeWithEnabledRules() {
        // Given
        helper.init(httpSenderNetwork);
        helper.hook(extensionHook);
        // When
        helper.getRateLimitOptions().addRule(enabledRule);
        helper.getRateLimitOptions().addRule(enabledRule2);
        // Then
        verify(httpSenderNetwork).setRateLimiter(any(NopRateLimiter.class));
        verify(httpSenderNetwork).setRateLimiter(any(RateLimiterImpl.class));
    }
}
