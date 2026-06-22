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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

/** Unit test for {@link AdaptiveWaitStrategy}. */
class AdaptiveWaitStrategyUnitTest {

    private static final String IN_SCOPE_URL = "http://example.com/api";
    private static final String OUT_OF_SCOPE_URL = "http://other.example.org/resource";
    private static final long INITIAL_PAGE_LOAD_TIME_MS =
            AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS + 1234L;
    private static final int PROXY_PORT = 8080;

    private AdaptiveWaitStrategy strategy;
    private ScheduledExecutorService scheduler;

    @BeforeEach
    void setUp() {
        strategy =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        ConcurrentHashMap.newKeySet(),
                        Duration.ofMillis(INITIAL_PAGE_LOAD_TIME_MS));

        WebDriverProcess wdp = mock();
        given(wdp.getProxyPort()).willReturn(PROXY_PORT);

        strategy.configure(wdp);
        scheduler = Executors.newScheduledThreadPool(2);
    }

    @AfterEach
    void tearDown() {
        scheduler.shutdownNow();
    }

    @Test
    void shouldReturnTrueOnceTrafficQuiesces() {
        // Given / when
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
    }

    @Test
    void shouldUseWithPageLoadThresholdWhenHintReceived() {
        // Given
        strategy.pageLoaded(IN_SCOPE_URL, PROXY_PORT);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
    }

    @Test
    void shouldWaitUntilInflightRequestCompletes() {
        // Given
        strategy.onRequestStarted(IN_SCOPE_URL);

        scheduler.schedule(
                () -> strategy.onRequestCompleted(IN_SCOPE_URL), 300, TimeUnit.MILLISECONDS);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(300L));
    }

    @Test
    void shouldNotCountOutOfScopeRequests() {
        // Given
        strategy.onRequestStarted(OUT_OF_SCOPE_URL);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldResetQuiesceClockWhenTrafficResumes() {
        // Given
        strategy.onRequestStarted(IN_SCOPE_URL);
        scheduler.schedule(
                () -> {
                    strategy.onRequestCompleted(IN_SCOPE_URL);
                    try {
                        Thread.sleep(30);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    strategy.onRequestStarted(IN_SCOPE_URL);
                    scheduler.schedule(
                            () -> strategy.onRequestCompleted(IN_SCOPE_URL),
                            300,
                            TimeUnit.MILLISECONDS);
                },
                200,
                TimeUnit.MILLISECONDS);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(500L));
    }

    @Test
    void shouldIgnorePageLoadFromDifferentProxyPort() {
        // Given
        int otherPort = PROXY_PORT + 1;
        strategy.pageLoaded(IN_SCOPE_URL, otherPort);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
    }

    @Test
    void shouldOnlyApplyHintFromMatchingProxyPort() {
        // Given
        strategy.pageLoaded(IN_SCOPE_URL, PROXY_PORT);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
    }

    @Test
    void shouldIgnorePageLoadBeforeOnStartIsCalled() {
        // Given
        AdaptiveWaitStrategy uninitialised =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        ConcurrentHashMap.newKeySet(),
                        Duration.ofMillis(INITIAL_PAGE_LOAD_TIME_MS));
        uninitialised.pageLoaded(IN_SCOPE_URL, PROXY_PORT);

        // When
        long start = System.currentTimeMillis();
        boolean result = uninitialised.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
    }

    @Test
    void shouldReturnTrueAfterHardTimeoutEvenIfTrafficNeverQuiesces() {
        // Given
        strategy.onRequestStarted(IN_SCOPE_URL);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldReturnFalseWhenInterrupted() throws InterruptedException {
        // Given
        strategy.onRequestStarted(IN_SCOPE_URL);
        AtomicBoolean returnValue = new AtomicBoolean(true);

        // When
        Thread t = new Thread(() -> returnValue.set(strategy.waitAfterAction()));
        t.start();
        Thread.sleep(200);
        t.interrupt();
        t.join(2000);

        // Then
        assertThat(returnValue.get(), is(false));
    }

    @Test
    void shouldUseInitialLoadTimeThresholdOnFirstWaitAfterPageLoad() {
        // Given / When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterPageLoad(IN_SCOPE_URL);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(INITIAL_PAGE_LOAD_TIME_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldUseRegularThresholdForSubsequentAccess() {
        // Given
        strategy.waitAfterPageLoad(IN_SCOPE_URL);

        //  When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterPageLoad(IN_SCOPE_URL);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
    }

    @Test
    void shouldUsePageLoadThresholdForKnownUrl() {
        // Given
        strategy.waitAfterPageLoad(IN_SCOPE_URL);
        strategy.pageLoaded(IN_SCOPE_URL, PROXY_PORT);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterPageLoad(IN_SCOPE_URL);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
    }

    @Test
    void shouldUseInitialLoadTimeOnFirstCallEvenWhenUrlAlreadyVisitedByAnotherStrategy() {
        // Given
        Set<String> sharedVisitedUrls = ConcurrentHashMap.newKeySet();
        Duration initialLoadTime = Duration.ofMillis(INITIAL_PAGE_LOAD_TIME_MS);

        AdaptiveWaitStrategy strategy1 =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        sharedVisitedUrls,
                        initialLoadTime);
        WebDriverProcess wdp = mock();
        given(wdp.getProxyPort()).willReturn(PROXY_PORT);
        strategy1.configure(wdp);
        strategy1.waitAfterPageLoad(IN_SCOPE_URL);

        AdaptiveWaitStrategy strategy2 =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        sharedVisitedUrls,
                        initialLoadTime);
        strategy2.configure(wdp);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy2.waitAfterPageLoad(IN_SCOPE_URL);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(INITIAL_PAGE_LOAD_TIME_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldResetPageLoadHintAtStartOfEachWait() {
        // Given
        strategy.pageLoaded(IN_SCOPE_URL, PROXY_PORT);
        strategy.waitAfterAction();

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_NO_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
    }

    @Test
    void shouldApplyHintWhenPageLoadArrivesWhileWaiting() {
        // Given
        scheduler.schedule(
                () -> strategy.pageLoaded(IN_SCOPE_URL, PROXY_PORT), 25, TimeUnit.MILLISECONDS);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_WITH_PAGE_LOAD_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
    }

    @Test
    void shouldReleaseWaitWhenFutureRequestCompletes() throws Exception {
        // Given
        Future<?> requestFuture =
                scheduler.schedule(
                        () -> strategy.onRequestStarted(IN_SCOPE_URL), 0, TimeUnit.MILLISECONDS);

        requestFuture.get(1, TimeUnit.SECONDS);

        scheduler.schedule(
                () -> strategy.onRequestCompleted(IN_SCOPE_URL), 400, TimeUnit.MILLISECONDS);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterAction();

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, greaterThanOrEqualTo(400L));
    }

    @Test
    void shouldUseUrlFirstAccessThresholdAfterInstanceFirstAccess() {
        // Given
        String secondUrl = "http://example.com/other";
        strategy.waitAfterPageLoad(IN_SCOPE_URL);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterPageLoad(secondUrl);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldUseUrlFirstAccessThresholdWhenInitialLoadTimeIsZero() {
        // Given
        strategy =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        ConcurrentHashMap.newKeySet(),
                        Duration.ofMillis(0L));
        String secondUrl = "http://example.com/other";
        strategy.waitAfterPageLoad(IN_SCOPE_URL);

        // When
        long start = System.currentTimeMillis();
        boolean result = strategy.waitAfterPageLoad(secondUrl);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(
                elapsed,
                greaterThanOrEqualTo(AdaptiveWaitStrategy.QUIESCE_THRESHOLD_FIRST_ACCESS_MS));
        assertThat(elapsed, lessThan(AdaptiveWaitStrategy.HARD_TIMEOUT_MS));
    }

    @Test
    void shouldNotUseInitialLoadTimeOnSubsequentCallsToSameUrl() {
        // Given
        AdaptiveWaitStrategy s =
                new AdaptiveWaitStrategy(
                        url -> url.startsWith("http://example.com"),
                        ConcurrentHashMap.newKeySet(),
                        Duration.ofMillis(INITIAL_PAGE_LOAD_TIME_MS));
        WebDriverProcess wdp = mock();
        given(wdp.getProxyPort()).willReturn(PROXY_PORT);
        s.configure(wdp);
        s.waitAfterPageLoad(IN_SCOPE_URL);

        // When
        long start = System.currentTimeMillis();
        boolean result = s.waitAfterPageLoad(IN_SCOPE_URL);

        // Then
        long elapsed = elapsed(start);
        assertThat(result, is(true));
        assertThat(elapsed, lessThan(INITIAL_PAGE_LOAD_TIME_MS));
    }

    private static long elapsed(long start) {
        return System.currentTimeMillis() - start;
    }
}
