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
package org.zaproxy.addon.exim.har;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link HarImporterType}. */
class HarImporterTypeUnitTest {

    private HarImporterType importer;

    @BeforeEach
    void setup() {
        importer = new HarImporterType();
    }

    private static Reader reader(String value) {
        return new StringReader(value);
    }

    @Test
    void shouldThrowIfMissingObjectStart() {
        // Given
        Reader reader = reader("");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(e.getMessage(), is(equalTo("Unexpected token null, expected: START_OBJECT")));
    }

    @Test
    void shouldThrowIfMissingLogField() {
        // Given
        Reader reader = reader("{}");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(
                e.getMessage(), is(equalTo("Unexpected token END_OBJECT, expected: FIELD_NAME")));
    }

    @Test
    void shouldThrowIfSomethingOtherThanLogField() {
        // Given
        Reader reader = reader("{\"not_log\":{}}");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(e.getMessage(), is(equalTo("Unexpected name not_log, expected: log")));
    }

    @Test
    void shouldThrowIfMissingLogObjectStart() {
        // Given
        Reader reader = reader("{\"log\":[]}");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(
                e.getMessage(),
                is(equalTo("Unexpected token START_ARRAY, expected: START_OBJECT")));
    }

    @Test
    void shouldThrowIfMissingEntriesField() {
        // Given
        Reader reader = reader("{\"log\":{}}");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(e.getMessage(), is(equalTo("Failed to find entries property in HAR log.")));
    }

    @Test
    void shouldThrowIfEntriesNotArray() {
        // Given
        Reader reader = reader("{\"log\":{\"entries\":{}}}");
        // When / Then
        IOException e = assertThrows(IOException.class, () -> importer.begin(reader));
        assertThat(
                e.getMessage(),
                is(equalTo("Unexpected token START_OBJECT, expected: START_ARRAY")));
    }

    @Test
    void shouldNotThrowIfEntriesAnArray() {
        // Given
        Reader reader = reader("{\"log\":{\"entries\":[]}}");
        // When / Then
        assertDoesNotThrow(() -> importer.begin(reader));
    }

    @Test
    void shouldNotThrowWhenReadingEnd() {
        // Given
        Reader reader = reader("…");
        // When / Then
        assertDoesNotThrow(() -> importer.end(reader));
    }
}
