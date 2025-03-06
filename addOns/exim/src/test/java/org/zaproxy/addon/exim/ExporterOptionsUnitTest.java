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
import org.zaproxy.addon.exim.ExporterOptions.Builder;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExporterOptions.Type;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ExporterOptions}. */
class ExporterOptionsUnitTest extends TestUtils {

    private Path outputFile;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionExim());
    }

    @BeforeEach
    void setup() {
        outputFile = Paths.get("/dir/file");
    }

    @Test
    void shouldFailToBuildWithoutOutputFile() {
        // Given
        Builder builder = ExporterOptions.builder();
        // When / Then
        Exception ex = assertThrows(IllegalStateException.class, () -> builder.build());
        assertThat(ex.getMessage(), containsString("outputFile"));
    }

    @Test
    void shouldBuildWithJustOutputFile() {
        // Given
        Builder builder = ExporterOptions.builder();
        // When
        ExporterOptions options = builder.setOutputFile(outputFile).build();
        // Then
        assertThat(options.getContext(), is(nullValue()));
        assertThat(options.getType(), is(equalTo(Type.HAR)));
        assertThat(options.getSource(), is(equalTo(Source.HISTORY)));
        assertThat(options.getOutputFile(), is(equalTo(outputFile)));
    }

    @Test
    void shouldSetContext() {
        // Given
        ExporterOptions.Builder builder = builderWithOutputFile();
        Context context = mock(Context.class);
        // When
        ExporterOptions options = builder.setContext(context).build();
        // Then
        assertThat(options.getContext(), is(equalTo(context)));
    }

    @ParameterizedTest
    @EnumSource(value = Type.class)
    void shouldSetType(Type type) {
        // Given
        ExporterOptions.Builder builder = builderWithOutputFile();
        // When
        ExporterOptions options = builder.setType(type).build();
        // Then
        assertThat(options.getType(), is(equalTo(type)));
    }

    @Test
    void shouldThrowSettingNullType() {
        // Given
        Builder builder = ExporterOptions.builder();
        // When / Then
        Exception ex = assertThrows(IllegalArgumentException.class, () -> builder.setType(null));
        assertThat(ex.getMessage(), containsString("type"));
    }

    @ParameterizedTest
    @EnumSource(value = Source.class)
    void shouldSetSource(Source source) {
        // Given
        ExporterOptions.Builder builder = builderWithOutputFile();
        // When
        ExporterOptions options = builder.setSource(source).build();
        // Then
        assertThat(options.getSource(), is(equalTo(source)));
    }

    @Test
    void shouldThrowSettingNullSource() {
        // Given
        Builder builder = ExporterOptions.builder();
        // When / Then
        Exception ex = assertThrows(IllegalArgumentException.class, () -> builder.setSource(null));
        assertThat(ex.getMessage(), containsString("source"));
    }

    private Builder builderWithOutputFile() {
        return ExporterOptions.builder().setOutputFile(outputFile);
    }

    /** Unit test for {@link ExporterOptions.Type}. */
    @Nested
    class TypeUnitTest {

        @ParameterizedTest
        @EnumSource(value = Type.class)
        void shouldHaveToStringRepresentation(Type type) {
            assertThat(type.toString(), is(notNullValue()));
        }

        @ParameterizedTest
        @CsvSource({"HAR, har", "URL, url"})
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
            "url, URL",
            "urL, URL"
        })
        void shouldConvertFromString(String value, Type expectedType) {
            assertThat(Type.fromString(value), is(equalTo(expectedType)));
        }
    }

    /** Unit test for {@link ExporterOptions.Source}. */
    @Nested
    class SourceUnitTest {

        @ParameterizedTest
        @EnumSource(value = Source.class)
        void shouldHaveToStringRepresentation(Source type) {
            assertThat(type.toString(), is(notNullValue()));
        }

        @ParameterizedTest
        @CsvSource({"HISTORY, history", "ALL, all"})
        void shouldReturnId(Source type, String expectedId) {
            assertThat(type.getId(), is(equalTo(expectedId)));
        }

        @ParameterizedTest
        @CsvSource({
            ", HISTORY",
            "'', HISTORY",
            "Something, HISTORY",
            "history, HISTORY",
            "historY, HISTORY",
            "all, ALL",
            "alL, ALL"
        })
        void shouldConvertFromString(String value, Source expectedSource) {
            assertThat(Source.fromString(value), is(equalTo(expectedSource)));
        }
    }
}
