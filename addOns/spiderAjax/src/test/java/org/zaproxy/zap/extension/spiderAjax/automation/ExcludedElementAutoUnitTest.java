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
package org.zaproxy.zap.extension.spiderAjax.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link ExcludedElementAuto}. */
class ExcludedElementAutoUnitTest {

    private ExcludedElementAuto element;

    @BeforeEach
    void setup() {
        element = new ExcludedElementAuto();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldBeAlwaysEnabled(boolean enabled) {
        // Given / When
        element.setEnabled(enabled);
        // Then
        assertThat(element.isEnabled(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotSerializeEnabledState(boolean enabled) {
        // Given
        element.setEnabled(enabled);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("enabled")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSerializeNullOrEmptyName(String name) {
        // Given
        element.setElement(name);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("name")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSerializeNullOrEmptyXpath(String xpath) {
        // Given
        element.setXpath(xpath);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("xpath")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSerializeNullOrEmptyText(String text) {
        // Given
        element.setText(text);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("text")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSerializeNullOrEmptyAttributeName(String text) {
        // Given
        element.setText(text);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("attributeName")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSerializeNullOrEmptyAttributeValue(String text) {
        // Given
        element.setText(text);
        // When
        String content = serialiazed(element);
        // Then
        assertThat(content, not(containsString("attributeValue")));
    }

    private static String serialiazed(ExcludedElementAuto element) {
        ObjectMapper objectMapper = new ObjectMapper(new YAMLFactory());
        try {
            return objectMapper.writeValueAsString(element);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
