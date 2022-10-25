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
package org.zaproxy.zap.extension.ascanrules.timing;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

import java.util.Random;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link TimingUtils}. */
class TimingUtilsUnitTest {

    private static final Random rand = new Random();
    private static int timesCalled = 0;

    @BeforeEach
    void init() {
        timesCalled = 0;
    }

    @Test
    // detect the case where the endpoint isn't injectable and responds quickly
    // should only send 1 request and then bail
    void shouldGiveUpQuicklyWhenNotInjectable() {
        // Given
        double[] independentVariables = {1, 2, 3, 4, 5};
        // When
        boolean result =
                TimingUtils.checkTimingDependence(
                        independentVariables,
                        // respond with a low time
                        (x) -> {
                            timesCalled += 1;
                            return 0.5;
                        },
                        0.1,
                        0.2);
        // Then
        assertThat(result, is(false));
        assertThat(timesCalled, is(1));
    }

    @Test
    // detect the case when the wait time is long, but not necessarily injectable
    // should only send 2-3 requests and then bail early
    void shouldGiveUpQuicklyWhenSlowButNotInjectable() {
        // Given
        double[] independentVariables = {1, 2, 3, 4, 5};
        // When
        boolean result =
                TimingUtils.checkTimingDependence(
                        independentVariables,
                        // source of small error
                        (x) -> {
                            timesCalled += 1;
                            return 10 + rand.nextDouble() * 0.5;
                        },
                        0.1,
                        0.2);
        // Then
        assertThat(result, is(false));
        assertThat(timesCalled, lessThanOrEqualTo(3));
    }

    @Test
    // verify the typical use case: detect correlation with relatively small noise
    void shouldDetectDependenceWithSmallError() {
        // Given
        double[] independentVariables = {1, 2, 3, 4, 5};
        double correlationErrorRange = 0.1;
        double slopeErrorRange = 0.2;
        // When
        boolean result =
                TimingUtils.checkTimingDependence(
                        independentVariables,
                        // source of small error
                        (x) -> x + rand.nextDouble(),
                        correlationErrorRange,
                        slopeErrorRange);
        // Then
        assertThat(result, is(true));
    }
}
