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
package org.zaproxy.addon.commonlib;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link DefaultValueProvider}. */
class DefaultValueProviderUnitTest {

    private DefaultValueProvider provider;

    @BeforeEach
    void setup() {
        provider = new DefaultValueProvider();
    }

    @Test
    void shouldGetValueWithNoInput() {
        // Given / When
        String value = provider.getValue(null, null, null, null, null, null, null);
        // Then
        assertThat(value, is(equalTo(DefaultValueProvider.DEFAULT_EMPTY_VALUE)));
    }

    @Test
    void shouldGetValueFromDefaultValue() {
        // Given
        String defaultValue = "Default Value";
        // When
        String value = provider.getValue(null, null, null, defaultValue, null, null, null);
        // Then
        assertThat(value, is(equalTo(defaultValue)));
    }

    @Test
    void shouldGetValueWithoutControlType() {
        // Given
        Map<String, String> fieldAttributes = Map.of();
        // When
        String value = provider.getValue(null, null, null, null, null, null, fieldAttributes);
        // Then
        assertThat(value, is(equalTo(DefaultValueProvider.DEFAULT_EMPTY_VALUE)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text", "TEXT", "Text"})
    void shouldGetValueForSimpleTextControlType(String type) {
        // Given
        Map<String, String> fieldAttributes =
                Map.of(DefaultValueProvider.CONTROL_TYPE_ATTRIBUTE, type);
        // When
        String value = provider.getValue(null, null, null, null, null, null, fieldAttributes);
        // Then
        assertThat(value, is(equalTo(DefaultValueProvider.DEFAULT_TEXT_VALUE)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "PASSWORD", "Password"})
    void shouldGetValueForPasswordControlType(String type) {
        // Given
        Map<String, String> fieldAttributes =
                Map.of(DefaultValueProvider.CONTROL_TYPE_ATTRIBUTE, type);
        // When
        String value = provider.getValue(null, null, null, null, null, null, fieldAttributes);
        // Then
        assertThat(value, is(equalTo(DefaultValueProvider.DEFAULT_PASS_VALUE)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"file", "FILE", "File"})
    void shouldGetValueForFileControlType(String type) {
        // Given
        Map<String, String> fieldAttributes =
                Map.of(DefaultValueProvider.CONTROL_TYPE_ATTRIBUTE, type);
        // When
        String value = provider.getValue(null, null, null, null, null, null, fieldAttributes);
        // Then
        assertThat(value, is(equalTo(DefaultValueProvider.DEFAULT_FILE_VALUE)));
    }
}
