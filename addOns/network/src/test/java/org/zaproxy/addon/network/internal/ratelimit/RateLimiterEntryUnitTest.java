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

import java.math.BigDecimal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RateLimiterEntryUnitTest {
    private RateLimiterKey key;

    @BeforeEach
    void setUp() {
        key = new RateLimiterKey("desc", "rule1");
    }

    @Test
    void shouldCorrectlyRecordRequest() {
        // Given
        RateLimiterEntry entry = new RateLimiterEntry(key);
        // Then
        assertThat(entry.getFirstRequestTime(), equalTo(0L));
        assertThat(entry.getLastRequestTime(), equalTo(0L));
        assertThat(entry.getRequestCount(), equalTo(0L));

        // When
        entry.recordRequest();
        // Then
        assertThat(entry.getFirstRequestTime(), not(equalTo(0L)));
        assertThat(entry.getLastRequestTime(), not(equalTo(0L)));
        assertThat(entry.getLastRequestTime(), equalTo(entry.getFirstRequestTime()));
        assertThat(entry.getRequestCount(), equalTo(1L));
    }

    @Test
    void shouldCalculateEffectiveRequestsPerSecond() {
        // Given
        RateLimiterEntry entry = new RateLimiterEntry(key);
        // Then
        assertThat(entry.getEffectiveRequestsPerSecond(), nullValue());

        // When
        entry.setFirstRequestTime(System.currentTimeMillis());
        entry.setLastRequestTime(entry.getFirstRequestTime() + 5000);
        entry.setRequestCount(10);
        // Then
        assertThat(entry.getEffectiveRequestsPerSecond(), equalTo(BigDecimal.valueOf(2)));
    }
}
