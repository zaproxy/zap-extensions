/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;

/** Unit test for {@link RegexPayloadGenerator}. */
class RegexPayloadGeneratorUnitTest {

    @Test
    void shouldCalculateNumberOfPayloadsWithNoLimit() {
        // Given
        String regex = "a{1,3}";
        int limit = 0;
        // When
        int count = RegexPayloadGenerator.calculateNumberOfPayloads(regex, limit);
        // Then
        assertThat(count, is(equalTo(3)));
    }

    @Test
    void shouldReturnDefaultLimitWhenCalculatingNumberOfPayloadsWithNoLimitAndInfiniteRegex() {
        // Given
        String regex = "a+";
        int limit = 0;
        // When
        int count = RegexPayloadGenerator.calculateNumberOfPayloads(regex, limit);
        // Then
        assertThat(count, is(equalTo(RegexPayloadGenerator.DEFAULT_LIMIT_CALCULATION_PAYLOADS)));
    }

    @Test
    void shouldCalculateNumberOfPayloadsWithNoLimitAndNoRandomOrder() {
        // Given
        String regex = "a{1,3}";
        int limit = 0;
        boolean random = false;
        // When
        int count = RegexPayloadGenerator.calculateNumberOfPayloads(regex, limit, random);
        // Then
        assertThat(count, is(equalTo(3)));
    }

    @Test
    void
            shouldReturnDefaultLimitWhenCalculatingNumberOfPayloadsWithNoLimitNoRandomOrderAndWithInfiniteRegex() {
        // Given
        String regex = "a+";
        int limit = 0;
        boolean random = false;
        // When
        int count = RegexPayloadGenerator.calculateNumberOfPayloads(regex, limit, random);
        // Then
        assertThat(count, is(equalTo(RegexPayloadGenerator.DEFAULT_LIMIT_CALCULATION_PAYLOADS)));
    }

    @Test
    void shouldReturnLimitWhenCalculatingNumberOfPayloadsWithRandomOrder() {
        // Given
        String regex = "a+";
        int limit = 50;
        boolean random = true;
        // When
        int count = RegexPayloadGenerator.calculateNumberOfPayloads(regex, limit, random);
        // Then
        assertThat(count, is(equalTo(limit)));
    }
}
