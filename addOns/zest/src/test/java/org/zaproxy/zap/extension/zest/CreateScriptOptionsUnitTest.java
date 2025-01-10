/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link CreateScriptOptions}. */
class CreateScriptOptionsUnitTest {

    @Test
    void shouldHaveExpectedDefaults() {
        // Given / When
        CreateScriptOptions options = CreateScriptOptions.DEFAULT;
        // Then
        assertThat(options.isAddStatusAssertion(), is(equalTo(false)));
        assertThat(options.isAddLengthAssertion(), is(equalTo(false)));
        assertThat(options.getLengthApprox(), is(equalTo(1)));
        assertThat(
                options.getIncludeResponses(),
                is(equalTo(CreateScriptOptions.IncludeResponses.GLOBAL_OPTION)));
        assertThat(options.isReplaceRequestValues(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAddStatusAssertion(boolean value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        builder.setAddStatusAssertion(value);
        // Then
        assertThat(builder.build().isAddStatusAssertion(), is(equalTo(value)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAddLengthAssertion(boolean value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        builder.setAddLengthAssertion(value);
        // Then
        assertThat(builder.build().isAddLengthAssertion(), is(equalTo(value)));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 10, 100, Integer.MAX_VALUE})
    void shouldSetLengthApprox(int value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        builder.setLengthApprox(value);
        // Then
        assertThat(builder.build().getLengthApprox(), is(equalTo(value)));
    }

    @ParameterizedTest
    @ValueSource(ints = {Integer.MIN_VALUE, -100, -10, -1})
    void shouldThrowSettingNegativeLengthApprox(int value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        Exception ex =
                assertThrows(IllegalArgumentException.class, () -> builder.setLengthApprox(value));
        // Then
        assertThat(ex.getMessage(), is(equalTo("The length must be zero or greater.")));
    }

    @ParameterizedTest
    @EnumSource(CreateScriptOptions.IncludeResponses.class)
    void shouldSetIncludeResponses(CreateScriptOptions.IncludeResponses value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        builder.setIncludeResponses(value);
        // Then
        assertThat(builder.build().getIncludeResponses(), is(equalTo(value)));
    }

    @Test
    void shouldThrowSettingNullIncludeResponses() {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        Exception ex =
                assertThrows(
                        IllegalArgumentException.class, () -> builder.setIncludeResponses(null));
        // Then
        assertThat(ex.getMessage(), is(equalTo("The include responses must not be null.")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetReplaceRequestValues(boolean value) {
        // Given
        var builder = CreateScriptOptions.builder();
        // When
        builder.setReplaceRequestValues(value);
        // Then
        assertThat(builder.build().isReplaceRequestValues(), is(equalTo(value)));
    }
}
