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

import java.util.List;
import org.parosproxy.paros.network.HttpMessage;

/** Rate Limiter that does nothing. */
public class NopRateLimiter implements RateLimiter {
    @Override
    public void configChange(RateLimitOptions param) {}

    @Override
    public void throttle(HttpMessage message, int initiator) {}

    @Override
    public List<RateLimiterEntry> getEntries() {
        return List.of();
    }

    @Override
    public void reset() {}

    @Override
    public void setObserver(Observer observer) {}

    @Override
    public void fireObserver() {}
}
