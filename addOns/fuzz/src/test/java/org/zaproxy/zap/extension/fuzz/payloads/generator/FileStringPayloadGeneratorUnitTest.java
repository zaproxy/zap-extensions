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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import static org.hamcrest.CoreMatchers.both;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThan;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator.DEFAULT_COMMENT_TOKEN;
import static org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator.NO_LIMIT;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/** Unit test for {@link FileStringPayloadGenerator}. */
class FileStringPayloadGeneratorUnitTest extends TestUtils {

    private static final boolean IGNORE_EMPTY_LINES = true;
    private static final boolean IGNORE_FIRST_LINE = false;

    @ParameterizedTest
    @MethodSource("constructorsFile")
    void shouldThrowOnNullFile(Function<Path, Executable> constructor) {
        // Given
        Path file = null;
        // When / Then
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, constructor.apply(file));
        assertThat(exception.getMessage(), containsString("file"));
    }

    static Stream<Function<Path, Executable>> constructorsFile() {
        return Stream.of(
                file -> () -> new FileStringPayloadGenerator(file),
                file -> () -> new FileStringPayloadGenerator(file, NO_LIMIT),
                file -> () -> new FileStringPayloadGenerator(file, NO_LIMIT, DEFAULT_COMMENT_TOKEN),
                file ->
                        () ->
                                new FileStringPayloadGenerator(
                                        file,
                                        StandardCharsets.UTF_8,
                                        NO_LIMIT,
                                        DEFAULT_COMMENT_TOKEN,
                                        IGNORE_EMPTY_LINES,
                                        IGNORE_FIRST_LINE),
                file ->
                        () ->
                                new FileStringPayloadGenerator(
                                        file,
                                        StandardCharsets.UTF_8,
                                        NO_LIMIT,
                                        DEFAULT_COMMENT_TOKEN,
                                        IGNORE_EMPTY_LINES,
                                        IGNORE_FIRST_LINE,
                                        0));
    }

    @ParameterizedTest
    @MethodSource("constructorsFile")
    void shouldThrowOnUnreadableFile(Function<Path, Executable> constructor) {
        // Given
        Path file = tempDir.resolve("not-a-readable-file.txt");
        // When / Then
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, constructor.apply(file));
        assertThat(exception.getMessage(), containsString("file"));
    }

    @ParameterizedTest
    @MethodSource("constructorsCharset")
    void shouldThrowOnNullCharset(Function<Charset, Executable> constructor) {
        // Given
        Charset charset = null;
        // When / Then
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, constructor.apply(charset));
        assertThat(exception.getMessage(), containsString("charset"));
    }

    static Stream<Function<Charset, Executable>> constructorsCharset() throws IOException {
        Path file = Files.createTempFile(tempDir, "fuzz", ".txt");
        return Stream.of(
                charset ->
                        () ->
                                new FileStringPayloadGenerator(
                                        file,
                                        charset,
                                        NO_LIMIT,
                                        DEFAULT_COMMENT_TOKEN,
                                        IGNORE_EMPTY_LINES,
                                        IGNORE_FIRST_LINE),
                charset ->
                        () ->
                                new FileStringPayloadGenerator(
                                        file,
                                        charset,
                                        NO_LIMIT,
                                        DEFAULT_COMMENT_TOKEN,
                                        IGNORE_EMPTY_LINES,
                                        IGNORE_FIRST_LINE,
                                        0));
    }

    @Test
    void shouldNotReadAllPayloadsWithIncorrectDefaultCharset() throws Exception {
        // Given
        long payloadCount = 5000;
        Path file = fileWithIso8859Payloads(payloadCount);
        // When
        FileStringPayloadGenerator generator = new FileStringPayloadGenerator(file);
        // Then
        assertThat(
                generator.getNumberOfPayloads(),
                is(both(greaterThan(0L)).and(lessThan(payloadCount))));
        assertThat(
                numberOfIteratedPayloads(generator),
                is(both(greaterThan(0L)).and(lessThan(payloadCount))));
    }

    @Test
    void shouldNotReadAllPayloadsWithIncorrectCharset() throws Exception {
        // Given
        long payloadCount = 5000;
        Path file = fileWithIso8859Payloads(payloadCount);
        Charset charset = StandardCharsets.UTF_8;
        // When
        FileStringPayloadGenerator generator =
                new FileStringPayloadGenerator(
                        file,
                        charset,
                        NO_LIMIT,
                        DEFAULT_COMMENT_TOKEN,
                        IGNORE_EMPTY_LINES,
                        IGNORE_FIRST_LINE);
        // Then
        assertThat(
                generator.getNumberOfPayloads(),
                is(both(greaterThan(0L)).and(lessThan(payloadCount))));
        assertThat(
                numberOfIteratedPayloads(generator),
                is(both(greaterThan(0L)).and(lessThan(payloadCount))));
    }

    @Test
    void shouldReadAllPayloadsWithCorrectCharset() throws Exception {
        // Given
        long payloadCount = 5000;
        Path file = fileWithIso8859Payloads(payloadCount);
        Charset charset = StandardCharsets.ISO_8859_1;
        // When
        FileStringPayloadGenerator generator =
                new FileStringPayloadGenerator(
                        file,
                        charset,
                        NO_LIMIT,
                        DEFAULT_COMMENT_TOKEN,
                        IGNORE_EMPTY_LINES,
                        IGNORE_FIRST_LINE);
        // Then
        assertThat(generator.getNumberOfPayloads(), is(equalTo(payloadCount)));
        assertThat(numberOfIteratedPayloads(generator), is(equalTo(payloadCount)));
    }

    private static Path fileWithIso8859Payloads(long count) throws IOException {
        Path file = Files.createTempFile(tempDir, "fuzz", ".txt");
        try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.ISO_8859_1)) {
            long total = count - 1;
            for (long i = 0; i < total; i++) {
                writer.append("0123456789ABCDEF").append('\n');
            }
            writer.append("Á").append('\n');
        }
        return file;
    }

    private static long numberOfIteratedPayloads(FileStringPayloadGenerator generator) {
        long count = 0;
        try (ResettableAutoCloseableIterator<DefaultPayload> iterator = generator.iterator()) {
            while (iterator.hasNext()) {
                iterator.next();
                count++;
            }
        }
        return count;
    }
}
