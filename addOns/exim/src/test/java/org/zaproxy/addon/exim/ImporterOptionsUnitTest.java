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
package org.zaproxy.addon.exim;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.zaproxy.addon.exim.ImporterOptions.Builder;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;
import org.zaproxy.addon.exim.ImporterOptions.Type;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ImporterOptions}. */
class ImporterOptionsUnitTest extends TestUtils {

    private Path inputFile;
    private MessageHandler messageHandler;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setup() {
        inputFile = Paths.get("/dir/file");
        messageHandler = msg -> {};
    }

    @Test
    void shouldFailToBuildWithoutInputFile() {
        // Given
        Builder builder = ImporterOptions.builder();
        // When / Then
        Exception ex = assertThrows(IllegalStateException.class, () -> builder.build());
        assertThat(ex.getMessage(), containsString("inputFile"));
    }

    @Test
    void shouldFailToBuildWithoutMessageHandler() {
        // Given
        Builder builder = ImporterOptions.builder().setInputFile(inputFile);
        // When / Then
        Exception ex = assertThrows(IllegalStateException.class, () -> builder.build());
        assertThat(ex.getMessage(), containsString("messageHandler"));
    }

    @Test
    void shouldBuildWithJustInputFileAndMessageHandler() {
        // Given
        Builder builder = ImporterOptions.builder();
        // When
        ImporterOptions options =
                builder.setInputFile(inputFile).setMessageHandler(messageHandler).build();
        // Then
        assertThat(options.getContext(), is(nullValue()));
        assertThat(options.getType(), is(equalTo(Type.HAR)));
        assertThat(options.getInputFile(), is(equalTo(inputFile)));
        assertThat(options.getMessageHandler(), is(equalTo(messageHandler)));
    }

    @Test
    void shouldSetContext() {
        // Given
        ImporterOptions.Builder builder = builderWithInputFileAndMessageHandler();
        Context context = mock(Context.class);
        // When
        ImporterOptions options = builder.setContext(context).build();
        // Then
        assertThat(options.getContext(), is(equalTo(context)));
    }

    @ParameterizedTest
    @EnumSource(value = Type.class)
    void shouldSetType(Type type) {
        // Given
        ImporterOptions.Builder builder = builderWithInputFileAndMessageHandler();
        // When
        ImporterOptions options = builder.setType(type).build();
        // Then
        assertThat(options.getType(), is(equalTo(type)));
    }

    @Test
    void shouldThrowSettingNullType() {
        // Given
        Builder builder = ImporterOptions.builder();
        // When / Then
        Exception ex = assertThrows(IllegalArgumentException.class, () -> builder.setType(null));
        assertThat(ex.getMessage(), containsString("type"));
    }

    private Builder builderWithInputFileAndMessageHandler() {
        return ImporterOptions.builder().setInputFile(inputFile).setMessageHandler(messageHandler);
    }

    /** Unit test for {@link ImporterOptions.Type}. */
    @Nested
    class TypeUnitTest {

        @ParameterizedTest
        @EnumSource(value = Type.class)
        void shouldHaveToStringRepresentation(Type type) {
            assertThat(type.toString(), is(notNullValue()));
        }

        @ParameterizedTest
        @CsvSource({"HAR, har"})
        void shouldReturnId(Type type, String expectedId) {
            assertThat(type.getId(), is(equalTo(expectedId)));
        }

        @ParameterizedTest
        @CsvSource({
            ", HAR",
            "'', HAR",
            "Something, HAR",
            "har, HAR",
            "haR, HAR",
        })
        void shouldConvertFromString(String value, Type expectedType) {
            assertThat(Type.fromString(value), is(equalTo(expectedType)));
        }
    }
}
