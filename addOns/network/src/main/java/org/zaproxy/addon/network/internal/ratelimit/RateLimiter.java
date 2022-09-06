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

import java.io.InterruptedIOException;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;

public interface RateLimiter extends RateLimitOptions.Observer {

    /**
     * Throttle the message rate according to the options.
     *
     * @param message the HTTP message.
     * @param initiator the initiator of the message.
     * @throws InterruptedIOException if interrupted while throttling.
     */
    void throttle(HttpMessage message, int initiator) throws InterruptedIOException;

    /** Get a snapshot view of the entries. */
    List<RateLimiterEntry> getEntries();

    /** Resets the internal state. */
    void reset();

    void setObserver(Observer observer);

    void fireObserver();

    interface Observer {
        void limiterUpdated(RateLimiter limiter);
    }
}
