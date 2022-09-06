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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.utils.Pair;

/** Track rate limiting. */
public class RateLimiterImpl implements RateLimiter {
    private static final Logger LOGGER = LogManager.getLogger(RateLimiterImpl.class);
    private final Map<RateLimiterKey, RateLimiterEntry> table = new ConcurrentHashMap<>();
    private List<RateLimitRule> rules = new ArrayList<>();
    private Observer observer;
    private WaitAction wait = new ThreadSleep();

    @Override
    public void throttle(HttpMessage message, int initiator) throws InterruptedIOException {
        if (rules.isEmpty()) {
            return;
        }
        Pair<RateLimiterEntry, RateLimitRule> entryAndRule = getOrCreate(message, initiator);
        if (entryAndRule == null) {
            LOGGER.debug("Rate limit not requested for {}", message.getRequestHeader().getURI());
            return;
        }
        RateLimiterEntry limiterEntry = entryAndRule.first;
        RateLimitRule rule = entryAndRule.second;
        synchronized (limiterEntry) {
            long millisToWait =
                    (1000 / rule.getRequestsPerSecond())
                            - (System.currentTimeMillis() - limiterEntry.getLastRequestTime());
            if (millisToWait > 0) {
                try {
                    LOGGER.debug(
                            "{}: sleeping for {} ms",
                            message.getRequestHeader().getURI(),
                            millisToWait);
                    wait.waitFor(millisToWait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new InterruptedIOException("Rate limit throttle interrupted");
                }
            }
            limiterEntry.recordRequest();
        }
        fireObserver();
    }

    /**
     * Update the limiter in response to configuration change.
     *
     * @param param the configuration
     */
    @Override
    public void configChange(RateLimitOptions param) {
        Set<String> enabledRules = new HashSet<>();
        List<RateLimitRule> newRules = new ArrayList<>(param.getRules().size());
        for (RateLimitRule rule : param.getRules()) {
            if (rule.isEnabled()) {
                newRules.add(new RateLimitRule(rule));
                enabledRules.add(rule.getDescription());
            }
        }
        rules = newRules;
        table.keySet().removeIf(key -> !enabledRules.contains(key.getRuleDescription()));
    }

    /**
     * Get the limiter entry for the message.
     *
     * @param msg the HTTP message.
     * @return entry and matching rule or null if no rules match.
     */
    Pair<RateLimiterEntry, RateLimitRule> getOrCreate(HttpMessage msg, int initiator) {
        RateLimitRule matchedRule = null;
        for (RateLimitRule rule : rules) {
            if (rule.isEnabled() && rule.appliesToInitiator(initiator) && rule.matches(msg)) {
                if (matchedRule == null
                        || rule.getRequestsPerSecond() < matchedRule.getRequestsPerSecond()) {
                    matchedRule = rule;
                }
            }
        }
        if (matchedRule == null) {
            return null;
        }

        String subKey;
        switch (matchedRule.getGroupBy()) {
            case RULE:
                subKey = matchedRule.getDescription();
                break;
            case HOST:
                try {
                    subKey = msg.getRequestHeader().getURI().getHost();
                } catch (NullPointerException | URIException e) {
                    return null;
                }
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported group by: " + matchedRule.getGroupBy());
        }

        RateLimiterKey key = new RateLimiterKey(matchedRule.getDescription(), subKey);
        return new Pair<>(table.computeIfAbsent(key, RateLimiterEntry::new), matchedRule);
    }

    @Override
    public List<RateLimiterEntry> getEntries() {
        return List.copyOf(table.values());
    }

    @Override
    public void reset() {
        table.clear();
        fireObserver();
    }

    @Override
    public void setObserver(Observer observer) {
        this.observer = observer;
        fireObserver();
    }

    @Override
    public void fireObserver() {
        if (observer != null) {
            observer.limiterUpdated(this);
        }
    }

    /** Set wait implementation. The default is to use Thread.sleep(...). */
    void setWait(WaitAction wait) {
        this.wait = Objects.requireNonNullElseGet(wait, ThreadSleep::new);
    }

    /** Defines a method for effecting a wait time on the current thread. */
    interface WaitAction {
        void waitFor(long millis) throws InterruptedException;
    }

    /** Uses Thread.sleep for rate limiting. */
    private static class ThreadSleep implements WaitAction {

        @Override
        public void waitFor(long millis) throws InterruptedException {
            Thread.sleep(millis);
        }
    }
}
