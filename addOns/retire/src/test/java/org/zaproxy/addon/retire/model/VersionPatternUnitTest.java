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
package org.zaproxy.addon.retire.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class VersionPatternUnitTest {

    private static Stream<Arguments> getFilenameTestValuesAndExpectedVersions() {
        return Stream.of(
                Arguments.of("bootstrap-3.1.1.min.js", "3.1.1"),
                Arguments.of("bootstrap-3_1_1.min.js", "3_1_1"),
                Arguments.of("bootstrap-3-1-1.min.js", "3-1-1"),
                Arguments.of("bootstrap-3.1.1.js", "3.1.1"),
                Arguments.of("bootstrap-3.1.1-alpha.js", "3.1.1-alpha"),
                Arguments.of("bootstrap-3.1.1-beta1.js", "3.1.1-beta1"));
    }

    @ParameterizedTest
    @MethodSource("getFilenameTestValuesAndExpectedVersions")
    void shouldMatchExpectedVersionStringInFilenames(String input, String expected) {
        // Given
        String pattern = "bootstrap-(§§version§§)(\\.min)?\\.js";
        // When
        String goodPattern = ExtractorsTypeAdapter.fixPattern(pattern);
        Pattern patternToTest = Pattern.compile(goodPattern);
        Matcher matcher = patternToTest.matcher(input);
        boolean matched = matcher.find();
        String matchedVersion = matcher.group(1);
        // Then
        assertTrue(matched);
        assertEquals(expected, matchedVersion);
    }

    private static Stream<Arguments> getContentTestValuesAndExpectedVersions() {
        return Stream.of(
                Arguments.of("/* Bootstrap v3.1.1-beta1 (foobar)", "3.1.1-beta1"),
                Arguments.of("/* Bootstrap v3.1.1-beta1\n", "3.1.1-beta1"),
                Arguments.of("/* Bootstrap v3.1.1\r\n", "3.1.1"),
                Arguments.of("/* Bootstrap v3.1.1\t(foorbar)", "3.1.1"));
    }

    @ParameterizedTest
    @MethodSource("getContentTestValuesAndExpectedVersions")
    void shouldMatchExpectedVersionStringInContent(String input, String expected) {
        // Given
        String pattern = "/\\*!? Bootstrap v(§§version§§)";
        // When
        String goodPattern = ExtractorsTypeAdapter.fixPattern(pattern);
        Pattern patternToTest = Pattern.compile(goodPattern);
        Matcher matcher = patternToTest.matcher(input);
        boolean matched = matcher.find();
        String matchedVersion = matcher.group(1);
        // Then
        assertTrue(matched);
        assertEquals(expected, matchedVersion);
    }
}
