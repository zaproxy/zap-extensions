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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class FormHandlerParamUnitTest {

    private static final String FORM_HANDLER_BASE_KEY = "formhandler";
    private static final String ALL_TOKENS_KEY = FORM_HANDLER_BASE_KEY + ".fields.field";
    private static final String TOKEN_NAME_KEY = "fieldId";
    private static final String TOKEN_VALUE_KEY = "value";
    private static final String TOKEN_ENABLED_KEY = "enabled";
    private static final String TOKEN_REGEX_KEY = "regex";

    private List<FormHandlerParamField> testFields =
            List.of(
                    new FormHandlerParamField("alice|bob", "example1", true, true),
                    new FormHandlerParamField("\\d{3}", "example2", true, true),
                    new FormHandlerParamField("foo|bar", "example3", true, true));

    private FormHandlerParam param;
    private ZapXmlConfiguration configuration;

    @BeforeEach
    void setUp() {
        param = new FormHandlerParam();
        configuration = new ZapXmlConfiguration();
        param.load(configuration);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(param.getConfigVersionKey(), is(equalTo("formhandler[@version]")));
    }

    @Test
    void shouldHaveExpectedNumberOfDefaultFieldDefinitions() {
        assertThat(param.getFields().size(), is(equalTo(19)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"FOO", "foo"})
    void shouldReturnSimpleMatchWhenAppropriate(String simple) {
        // Given
        List<FormHandlerParamField> fields =
                List.of(new FormHandlerParamField("foo", "example", true, false));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue(simple);
        // Then
        assertThat(value, is(equalTo("example")));
    }

    @Test
    void shouldReturnSimpleMatchWhenMatchAmongstMany() {
        // Given
        List<FormHandlerParamField> fields =
                List.of(
                        new FormHandlerParamField("alice", "example1", true, false),
                        new FormHandlerParamField("bob", "example2", true, false),
                        new FormHandlerParamField("foo", "example3", true, false));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("foo");
        // Then
        assertThat(value, is(equalTo("example3")));
    }

    @Test
    void shouldNotReturnSimpleMatchWhenNoMatch() {
        // Given
        List<FormHandlerParamField> fields =
                List.of(new FormHandlerParamField("foo", "example", true, false));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("alice");
        // Then
        assertThat(value, is(equalTo(null)));
    }

    @Test
    void shouldNotReturnSimpleMatchAmongstManyIfDisabled() {
        // Given
        List<FormHandlerParamField> fields =
                List.of(
                        new FormHandlerParamField("alice", "example1", true, false),
                        new FormHandlerParamField("bob", "example2", true, false),
                        new FormHandlerParamField("foo", "example3", false, false));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("foo");
        // Then
        assertThat(value, is(equalTo(null)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"(?i)FOO|BAR", "foo|bar", "^bar$"})
    void shouldReturnRegexMatchWhenAppropriate(String regex) {
        // Given
        List<FormHandlerParamField> fields =
                List.of(new FormHandlerParamField(regex, "example", true, true));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("bar");
        // Then
        assertThat(value, is(equalTo("example")));
    }

    @Test
    void shouldReturnSimpleMatchBeforeRegexMatchWhenMatchAmongstMany() {
        // Given
        List<FormHandlerParamField> fields = new ArrayList<>();
        fields.addAll(testFields);
        fields.add(new FormHandlerParamField("foo", "example4", true, false));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("foo");
        // Then
        assertThat(value, is(equalTo("example4")));
    }

    @Test
    void shouldReturnRegexMatchWhenNoSimpleMatchAmongstMany() {
        // Given
        List<FormHandlerParamField> fields =
                List.of(
                        new FormHandlerParamField("alice", "example1"),
                        new FormHandlerParamField("bob", "example2"),
                        new FormHandlerParamField("foo|bar", "example3", true, true));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("foo");
        // Then
        assertThat(value, is(equalTo("example3")));
    }

    @Test
    void shouldNotReturnRegexMatchWhenNoMatch() {
        // Given
        List<FormHandlerParamField> fields =
                List.of(new FormHandlerParamField("foo|bar", "example", true, true));
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("alice");
        // Then
        assertThat(value, is(equalTo(null)));
    }

    @Test
    void shouldNotReturnRegexMatchAmongstManyIfDisabled() {
        // Given
        List<FormHandlerParamField> fields = new ArrayList<>();
        fields.addAll(testFields);
        fields.get(2).setEnabled(false);
        param.setFields(fields);
        // When
        String value = param.getEnabledFieldValue("foo");
        // Then
        assertThat(value, is(equalTo(null)));
    }

    @Test
    void shouldNotSetInvalidRegex() {
        // Given
        List<FormHandlerParamField> fields = new ArrayList<>();
        fields.addAll(FormHandlerParam.DEFAULT_FIELDS_ORIGINAL);
        fields.addAll(FormHandlerParam.DEFAULT_FIELDS_V1);
        fields.addAll(testFields);
        fields.add(new FormHandlerParamField("\\d{9", "example4", true, true));
        configuration = buildConfig(configuration, fields);
        // When
        param.load(configuration);
        int fieldsCount = param.getFields().size();
        int enabledFieldsCount = param.getEnabledFieldsNames().size();
        // Then
        assertThat(fieldsCount, is(equalTo(22)));
        assertThat(enabledFieldsCount, is(equalTo(22)));
    }

    @Test
    void shouldSetOnlyV1WhenSingleOriginalExists() {
        // Given
        List<FormHandlerParamField> fields = new ArrayList<>();
        fields.add(FormHandlerParam.DEFAULT_FIELDS_ORIGINAL.get(0));
        configuration = buildConfig(new ZapXmlConfiguration(), fields);
        // When
        param.load(configuration);
        // Then
        List<FormHandlerParamField> loadedFields = param.getFields();
        int fieldsCount = loadedFields.size();
        int enabledFieldsCount = param.getEnabledFieldsNames().size();
        assertThat(
                loadedFields.get(0), is(equalTo(FormHandlerParam.DEFAULT_FIELDS_ORIGINAL.get(0))));
        assertThat(loadedFields.get(1), is(equalTo(FormHandlerParam.DEFAULT_FIELDS_V1.get(0))));
        assertThat(loadedFields.get(2), is(equalTo(FormHandlerParam.DEFAULT_FIELDS_V1.get(1))));
        assertThat(fieldsCount, is(equalTo(FormHandlerParam.DEFAULT_FIELDS_V1.size() + 1)));
        assertThat(enabledFieldsCount, is(equalTo(FormHandlerParam.DEFAULT_FIELDS_V1.size() + 1)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"color"})
    @NullAndEmptySource
    void shouldTNothrowExceptionWhenRemovingField(String name) {
        // Given
        List<FormHandlerParamField> fields = new ArrayList<>();
        fields.add(FormHandlerParam.DEFAULT_FIELDS_ORIGINAL.get(0)); // color
        fields.add(FormHandlerParam.DEFAULT_FIELDS_ORIGINAL.get(1)); // email
        configuration = buildConfig(new ZapXmlConfiguration(), fields);
        // Given / When
        param.load(configuration);
        // Then
        assertDoesNotThrow(() -> param.removeField(name));
    }

    private ZapXmlConfiguration buildConfig(
            ZapXmlConfiguration config, List<FormHandlerParamField> fields) {
        for (int i = 0, size = fields.size(); i < size; ++i) {
            String elementBaseKey = ALL_TOKENS_KEY + "(" + i + ").";
            FormHandlerParamField field = fields.get(i);
            config.setProperty(elementBaseKey + TOKEN_NAME_KEY, field.getName());
            config.setProperty(elementBaseKey + TOKEN_VALUE_KEY, field.getValue());
            config.setProperty(
                    elementBaseKey + TOKEN_ENABLED_KEY, Boolean.valueOf(field.isEnabled()));
            config.setProperty(elementBaseKey + TOKEN_REGEX_KEY, Boolean.valueOf(field.isRegex()));
        }
        return config;
    }
}
