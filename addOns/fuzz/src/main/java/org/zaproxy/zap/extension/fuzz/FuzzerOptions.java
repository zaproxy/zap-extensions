/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.util.concurrent.TimeUnit;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationsReplacementStrategy;

public class FuzzerOptions {

    private final int threadCount;
    private final int retriesOnIOError;
    private final int maxErrorsAllowed;
    private final long sendMessageDelay;
    private final TimeUnit sendMessageDelayUnit;
    private final MessageLocationsReplacementStrategy payloadsReplacementStrategy;

    public FuzzerOptions(
            int threadCount,
            int retriesOnIOError,
            int maxErrorsAllowed,
            long sendMessageDelay,
            TimeUnit sendMessageDelayUnit,
            MessageLocationsReplacementStrategy payloadsReplacementStrategy) {
        this.threadCount = threadCount;
        this.retriesOnIOError = retriesOnIOError;
        this.maxErrorsAllowed = maxErrorsAllowed;
        this.sendMessageDelay = sendMessageDelay;
        this.sendMessageDelayUnit = sendMessageDelayUnit;
        this.payloadsReplacementStrategy = payloadsReplacementStrategy;
    }

    protected FuzzerOptions(FuzzerOptions other) {
        this.threadCount = other.threadCount;
        this.retriesOnIOError = other.retriesOnIOError;
        this.maxErrorsAllowed = other.maxErrorsAllowed;
        this.sendMessageDelay = other.sendMessageDelay;
        this.sendMessageDelayUnit = other.sendMessageDelayUnit;
        this.payloadsReplacementStrategy = other.payloadsReplacementStrategy;
    }

    public int getThreadCount() {
        return threadCount;
    }

    public int getRetriesOnIOError() {
        return retriesOnIOError;
    }

    public int getMaxErrorsAllowed() {
        return maxErrorsAllowed;
    }

    public long getSendMessageDelay() {
        return sendMessageDelay;
    }

    public TimeUnit getSendMessageDelayTimeUnit() {
        return sendMessageDelayUnit;
    }

    public MessageLocationsReplacementStrategy getPayloadsReplacementStrategy() {
        return payloadsReplacementStrategy;
    }
}
