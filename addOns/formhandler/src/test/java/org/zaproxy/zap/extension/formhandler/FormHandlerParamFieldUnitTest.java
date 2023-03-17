/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class FormHandlerParamFieldUnitTest {

    @Test
    void shouldThrowNpeIfConstructedWithNullName() {
        assertThrows(
                NullPointerException.class,
                () -> new FormHandlerParamField(null, "bar", true, false));
    }

    @Test
    void shouldThrowNpeIfConstructedWithNullValue() {
        assertThrows(
                NullPointerException.class,
                () -> new FormHandlerParamField("foo", null, true, false));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sameParamFieldsShouldBeEqual(boolean regex) {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField("foo", "bar", true, regex);
        FormHandlerParamField field2 = new FormHandlerParamField("foo", "bar", true, regex);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"bob"})
    @EmptySource
    void paramFieldsShouldDifferName(String name) {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField("foo", "bar", true, false);
        FormHandlerParamField field2 = new FormHandlerParamField(name, "bar", true, false);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({"foo, bar", "foo|bar, bob|alice", "bob, foo|bar"})
    void paramFieldsWithDifferentNamesShouldNotBeEqual(String nameOne, String nameTwo) {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField(nameOne, "bar", true, true);
        FormHandlerParamField field2 = new FormHandlerParamField(nameTwo, "bar", true, true);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"bob"})
    @EmptySource
    void sameParamFieldsShouldDifferOnValue(String value) {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField("foo", "bar", true, false);
        FormHandlerParamField field2 = new FormHandlerParamField("foo", value, true, true);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void sameParamFieldsShouldDifferOnEnableState() {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField("foo", "bar", false, true);
        FormHandlerParamField field2 = new FormHandlerParamField("foo", "bar", true, true);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void sameParamFieldsShouldDifferOnRegexState() {
        // Given
        FormHandlerParamField field1 = new FormHandlerParamField("foo", "bar", true, false);
        FormHandlerParamField field2 = new FormHandlerParamField("foo", "bar", true, true);
        // When
        boolean result = field1.equals(field2);
        // Then
        assertThat(result, is(equalTo(false)));
    }
}
