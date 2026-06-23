/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

public class AdaptiveWaitStrategy implements ActionWaitStrategy {

    private static final Logger LOGGER = LogManager.getLogger(AdaptiveWaitStrategy.class);

    static final long POLL_INTERVAL_MS = 50;

    static final long QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS = 100;
    static final long QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS = 50;

    private final long timeoutMs;
    private final long quiesceFirstAccessMs;
    private final long initialLoadTimeMs;
    private final Predicate<String> urlInScope;
    private final AtomicInteger inflightInScopeCount = new AtomicInteger();
    private final Set<String> visitedUrls;

    private volatile int proxyPort;
    private volatile boolean pageLoadReceived;
    private boolean firstAccess;

    public AdaptiveWaitStrategy(
            ClientSpiderOptions options, Predicate<String> urlInScope, Set<String> visitedUrls) {
        this.timeoutMs = options.getAdaptiveTimeout();
        this.quiesceFirstAccessMs = options.getAdaptiveQuiesceFirstAccess();
        this.urlInScope = urlInScope;
        this.visitedUrls = visitedUrls;
        this.initialLoadTimeMs = TimeUnit.SECONDS.toMillis(options.getInitialLoadTimeInSecs());
        firstAccess = initialLoadTimeMs > 0;
    }

    @Override
    public void configure(WebDriverProcess wdp) {
        this.proxyPort = wdp.getProxyPort();
    }

    @Override
    public void onRequestStarted(String url) {
        if (urlInScope.test(url)) {
            inflightInScopeCount.incrementAndGet();
        }
    }

    @Override
    public void onRequestCompleted(String url) {
        if (urlInScope.test(url)) {
            inflightInScopeCount.decrementAndGet();
        }
    }

    @Override
    public void pageLoaded(String url, int source) {
        if (source == proxyPort) {
            pageLoadReceived = true;
        }
    }

    @Override
    public boolean waitAfterAction() {
        return waitForStability(false, false);
    }

    @Override
    public boolean waitAfterPageLoad(String url) {
        boolean urlFirstAccess = visitedUrls.add(url);
        boolean instanceFirst = firstAccess;
        if (instanceFirst) {
            firstAccess = false;
        }
        return waitForStability(instanceFirst, urlFirstAccess);
    }

    private boolean waitForStability(boolean instanceFirst, boolean urlFirstAccess) {
        long start = System.currentTimeMillis();
        long quiesceStart = -1;

        while (true) {
            long now = System.currentTimeMillis();
            if (now - start >= timeoutMs) {
                LOGGER.debug("Adaptive wait timeout reached after {}ms", timeoutMs);
                break;
            }

            int inflight = inflightInScopeCount.get();
            if (inflight == 0) {
                if (quiesceStart < 0) {
                    quiesceStart = now;
                }
                long threshold;
                if (instanceFirst) {
                    threshold = initialLoadTimeMs;
                } else if (urlFirstAccess) {
                    threshold = quiesceFirstAccessMs;
                } else {
                    threshold =
                            pageLoadReceived
                                    ? QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS
                                    : QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS;
                }
                if (now - quiesceStart >= threshold) {
                    break;
                }
            } else {
                quiesceStart = -1;
            }

            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                LOGGER.debug("Interrupted while waiting for stability.");
                pageLoadReceived = false;
                return false;
            }
        }
        inflightInScopeCount.set(0);
        pageLoadReceived = false;
        return true;
    }
}
