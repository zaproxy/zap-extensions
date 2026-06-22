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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Options;
import org.openqa.selenium.WebDriver.Timeouts;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

/** Unit test for {@link FixedWaitStrategy}. */
class FixedWaitStrategyUnitTest {

    private FixedWaitStrategy strategy;

    @Test
    void shouldSleepForInitialLoadTimeOnFirstWaitAfterPageLoad() {
        // Given
        strategy = new FixedWaitStrategy(millis(300L), millis(0L), millis(0L));
        long start = System.currentTimeMillis();

        // When
        boolean result = strategy.waitAfterPageLoad("http://example.com/");

        // Then
        assertThat(result, is(true));
        assertThat(elapsed(start), is(greaterThanOrEqualTo(300L)));
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 1_000L, 10_000L})
    void shouldReturnImmediatelyOnSubsequentWaitAfterPageLoad(long time) {
        // Given
        strategy = new FixedWaitStrategy(millis(time), millis(2000L), millis(0L));
        strategy.waitAfterPageLoad("http://example.com/");
        long start = System.currentTimeMillis();

        // When
        boolean result = strategy.waitAfterPageLoad("http://example.com/");

        // Then
        assertThat(result, is(true));
        assertThat(elapsed(start), is(lessThan(50L)));
    }

    @Test
    void shouldReturnImmediatelyWhenInitialLoadTimeIsZero() {
        // Given
        strategy = new FixedWaitStrategy(millis(0L), millis(1000L), millis(0L));
        long start = System.currentTimeMillis();

        // When
        boolean result = strategy.waitAfterPageLoad("http://example.com/");

        // Then
        assertThat(result, is(true));
        assertThat(elapsed(start), is(lessThan(50L)));
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 1_000L, 10_000L})
    void shouldConfigureWebDriverPageLoadTimeout(long time) {
        // Given
        Duration expectedDuration = millis(time);
        strategy = new FixedWaitStrategy(millis(0L), expectedDuration, millis(2000L));
        WebDriverProcess wdp = mock();
        WebDriver wd = mock();
        given(wdp.getWebDriver()).willReturn(wd);
        Options options = mock();
        given(wd.manage()).willReturn(options);
        Timeouts timeouts = mock();
        given(options.timeouts()).willReturn(timeouts);

        // When
        strategy.configure(wdp);

        // Then
        verify(timeouts).pageLoadTimeout(expectedDuration);
    }

    @Test
    void shouldSleepForActionWaitDuration() {
        // Given
        strategy = new FixedWaitStrategy(millis(0L), millis(1000L), millis(500L));
        long start = System.currentTimeMillis();

        // When
        boolean result = strategy.waitAfterAction();

        // Then
        assertThat(result, is(true));
        assertThat(elapsed(start), is(greaterThanOrEqualTo(500L)));
    }

    @Test
    void shouldReturnFalseAndRestoreInterruptOnActionWaitInterruption()
            throws InterruptedException {
        // Given
        strategy = new FixedWaitStrategy(millis(0L), millis(1000L), millis(2000L));
        AtomicBoolean returnValue = new AtomicBoolean(true);
        Thread t = new Thread(() -> returnValue.set(strategy.waitAfterAction()));

        t.start();
        // When
        t.interrupt();
        t.join(2000);

        // Then
        assertThat(returnValue.get(), is(false));
    }

    @Test
    void shouldIgnoreTrafficHooks() {
        // Given
        strategy = new FixedWaitStrategy(millis(0L), millis(1000L), millis(2000L));

        // When / Then
        assertDoesNotThrow(() -> strategy.onRequestStarted("http://example.com/"));
        assertDoesNotThrow(() -> strategy.onRequestCompleted("http://example.com/"));
    }

    @Test
    void shouldIgnorePageLoadEvents() {
        // Given
        strategy = new FixedWaitStrategy(millis(0L), millis(1000L), millis(2000L));

        // When / Then
        assertDoesNotThrow(() -> strategy.pageLoaded("http://example.com/", 8080));
    }

    private static Duration millis(long time) {
        return Duration.ofMillis(time);
    }

    private static long elapsed(long start) {
        return System.currentTimeMillis() - start;
    }
}
