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
package org.zaproxy.addon.network.server;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link ChunkedOutputStream}. */
class ChunkedOutputStreamUnitTest {

    private List<String> writes;
    private boolean wrappedClosed;
    private boolean failWrites;
    private ChunkedOutputStream stream;

    @BeforeEach
    void setUp() {
        writes = new ArrayList<>();
        stream =
                new ChunkedOutputStream(
                        new OutputStream() {
                            private final ByteArrayOutputStream buffer =
                                    new ByteArrayOutputStream();

                            @Override
                            public void write(int b) throws IOException {
                                write(new byte[] {(byte) b}, 0, 1);
                            }

                            @Override
                            public void write(byte[] b, int off, int len) throws IOException {
                                if (failWrites) {
                                    throw new IOException("failed");
                                }
                                writes.add(new String(b, off, len, StandardCharsets.US_ASCII));
                            }

                            @Override
                            public void close() {
                                wrappedClosed = true;
                            }
                        });
    }

    @Test
    void shouldThrowOnNullStream() {
        assertThrows(NullPointerException.class, () -> new ChunkedOutputStream(null));
    }

    @Test
    void shouldWriteEachWriteAsOneChunk() throws Exception {
        // When
        stream.write("abc".getBytes(StandardCharsets.US_ASCII));
        stream.write('d');
        stream.write("abcdef".getBytes(StandardCharsets.US_ASCII), 2, 3);
        // Then
        assertThat(writes, contains("3\r\nabc\r\n", "1\r\nd\r\n", "3\r\ncde\r\n"));
    }

    @Test
    void shouldWriteSizeInHex() throws Exception {
        // When
        stream.write(new byte[26]);
        // Then
        assertThat(writes.get(0).startsWith("1a\r\n"), is(true));
    }

    @Test
    void shouldNotWriteEmptyChunk() throws Exception {
        // When
        stream.write(new byte[0]);
        // Then
        assertThat(writes.isEmpty(), is(true));
    }

    @Test
    void shouldFailToWriteInvalidRange() {
        assertThrows(IndexOutOfBoundsException.class, () -> stream.write(new byte[2], 1, 2));
    }

    @Test
    void shouldWriteLastChunkAndCloseWrappedStreamOnce() throws Exception {
        // When
        stream.close();
        stream.close();
        // Then
        assertThat(writes, contains("0\r\n\r\n"));
        assertThat(wrappedClosed, is(true));
    }

    @Test
    void shouldCloseWrappedStreamIfLastChunkFails() {
        // Given
        failWrites = true;
        // When
        assertThrows(IOException.class, () -> stream.close());
        // Then
        assertThat(wrappedClosed, is(true));
    }

    @Test
    void shouldFailToWriteAfterClose() throws Exception {
        // Given
        stream.close();
        // When / Then
        assertThrows(IOException.class, () -> stream.write('a'));
    }

    @Test
    void shouldPassOnWriteFailures() {
        // Given
        failWrites = true;
        // When / Then
        assertThrows(IOException.class, () -> stream.write('a'));
        assertThat(wrappedClosed, is(equalTo(false)));
    }
}
