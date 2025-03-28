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
package org.zaproxy.zap.extension.formhandler;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

/** Unit test for {@link FormHandlerValueProvider}. */
class FormHandlerValueGeneratorUnitTest {

    private FormHandlerParam param;
    private FormHandlerValueProvider valueGenerator;

    @BeforeEach
    void setUp() {
        param = mock(FormHandlerParam.class);
        valueGenerator = new FormHandlerValueProvider(param);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldReturnEmptyStringForUnidentifiedFields(String fieldId) {
        // Given / When
        String generatedvalue =
                valueGenerator.getValue(null, null, fieldId, null, null, null, null);
        // Then
        assertThat(generatedvalue, is(equalTo("")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldUseDefaultValueWhenAvailableForUnidentifiedFields(String fieldId) {
        // Given
        String defaultValue = "DefaultValue";
        // When
        String generatedvalue =
                valueGenerator.getValue(null, null, fieldId, defaultValue, null, null, null);
        // Then
        assertThat(generatedvalue, is(equalTo(defaultValue)));
    }

    @Test
    void shouldCallGetEnabledFieldValue() {
        // Given
        String value = "foobar";
        given(param.getEnabledFieldValue("bar")).willReturn(value);
        // When
        String generatedvalue = valueGenerator.getValue(null, null, "bar", "bob", null, null, null);
        // Then
        assertThat(generatedvalue, is(equalTo(value)));
        verify(param, times(1)).getEnabledFieldValue(any());
    }
}
