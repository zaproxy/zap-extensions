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

import java.math.BigDecimal;
import java.math.RoundingMode;

/** Tracks a single entry (based on RateLimitGroupBy). */
public class RateLimiterEntry {
    private final RateLimiterKey key;
    private long firstRequestTime;
    private long lastRequestTime;
    private long requestCount;

    public RateLimiterEntry(RateLimiterKey key) {
        this.key = key;
    }

    public RateLimiterKey getKey() {
        return key;
    }

    public long getFirstRequestTime() {
        return firstRequestTime;
    }

    public void setFirstRequestTime(long firstRequestTime) {
        this.firstRequestTime = firstRequestTime;
    }

    public long getLastRequestTime() {
        return lastRequestTime;
    }

    public void setLastRequestTime(long lastRequestTime) {
        this.lastRequestTime = lastRequestTime;
    }

    public long getRequestCount() {
        return requestCount;
    }

    public void setRequestCount(long requestCount) {
        this.requestCount = requestCount;
    }

    public void recordRequest() {
        if (firstRequestTime == 0) {
            firstRequestTime = System.currentTimeMillis();
        }
        requestCount++;
        lastRequestTime = System.currentTimeMillis();
    }

    public BigDecimal getEffectiveRequestsPerSecond() {
        if (requestCount == 0 || firstRequestTime == 0) {
            return null;
        }
        long elapsed = lastRequestTime - firstRequestTime;
        if (elapsed <= 0) {
            return null;
        }
        BigDecimal n = BigDecimal.valueOf(requestCount);
        BigDecimal d =
                BigDecimal.valueOf(elapsed).divide(BigDecimal.valueOf(1000), RoundingMode.UP);
        return n.divide(d, RoundingMode.UP);
    }
}
