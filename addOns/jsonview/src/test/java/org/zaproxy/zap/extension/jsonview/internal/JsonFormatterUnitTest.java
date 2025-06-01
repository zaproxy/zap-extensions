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
package org.zaproxy.zap.extension.jsonview.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link JsonFormatter}. */
class JsonFormatterUnitTest {

    static Stream<String> invalidJson() {
        return Stream.of(
                "\t notliteral \t",
                "\t +1 \t",
                "\t 1E/1 \t",
                "\t { not object } \t",
                "\t [ not array ] \t");
    }

    @ParameterizedTest
    @MethodSource("invalidJson")
    void shouldNotBeJsonIfInvalidJson(String original) {
        // Given / When
        boolean json = JsonFormatter.isJson(original);
        // Then
        assertThat(json, is(equalTo(false)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"false", "null", "true", "1", "[]", "{}"})
    void shouldBeJsonIfValidJsonOrNullOrEmpty(String original) {
        // Given / When
        boolean json = JsonFormatter.isJson(original);
        // Then
        assertThat(json, is(equalTo(true)));
    }

    @ParameterizedTest
    @CsvSource({"'\t false ',false", "'\t null ',null", "'\t true ',true"})
    void shouldFormatLiteralNames(String original, String expected) {
        testFormattedValue(original, expected);
    }

    @ParameterizedTest
    @CsvSource({
        "'\t -1 ',-1",
        "'\t 1 ',1",
        "'\t 1.2 ',1.2",
        "'\t 1E1 ',10.0",
        "'\t 1E+1 ',10.0",
        "'\t 1E-1 ',0.1",
        "'\t 0.2E+2 ',20.0",
        "'\t 0.2E-1 ',0.02"
    })
    void shouldFormatNumbers(String original, String expected) {
        testFormattedValue(original, expected);
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "'\t \"\" ',\"\"",
                "'\t  \"escaped chars \\t \\n \\\"  \"   \t','\"escaped chars \\t \\n \\\"  \"'"
            })
    void shouldFormatStrings(String original, String expected) {
        testFormattedValue(original, expected);
    }

    @ParameterizedTest
    @CsvSource(value = {"'\t [] ',[ ]", "'\t  [1, null, {}, \"\"]','[ 1, null, { }, \"\" ]'"})
    void shouldFormatArrays(String original, String expected) {
        testFormattedValue(original, expected);
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "'\t {} ','{ }'",
                "'\t  {\"a\": {}, \"b\":\"{}\"}','{\n  \"a\" : { },\n  \"b\" : \"{}\"\n}'"
            })
    void shouldFormatObjects(String original, String expected) {
        testFormattedValue(original, adjustLineSeparator(expected));
    }

    private static String adjustLineSeparator(String value) {
        return value.replace("\n", System.getProperty("line.separator"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @MethodSource("invalidJson")
    void shouldNotFormatInvalidJson(String original) {
        testFormattedValue(original, original);
    }

    private static void testFormattedValue(String original, String expected) {
        // Given / When
        String formatted = JsonFormatter.toFormattedJson(original);
        // Then
        assertThat(formatted, is(equalTo(expected)));
    }
}
