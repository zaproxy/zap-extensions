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
package org.zaproxy.addon.dev.streaming;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link StreamPage}. */
class StreamPageUnitTest {

    private TestProxyServer server;
    private HttpMessageHandlerContext ctx;
    private ClosableByteArrayOutputStream out;

    @BeforeEach
    void setUp() throws Exception {
        server = mock(TestProxyServer.class);
        ctx = mock(HttpMessageHandlerContext.class);
        out = new ClosableByteArrayOutputStream();
        given(ctx.streamingResponse(any())).willReturn(out);
    }

    @Test
    void shouldStreamPreambleAndChunksThenEnd() throws Exception {
        // Given
        StreamPage page =
                new StreamPage(server, "p", "text/plain", "start;", i -> "c" + i + ";", 1, 30, 100);
        HttpMessage msg = request("/p");
        // When
        page.handleMessage(ctx, msg);
        // Then
        String body = out.toString(StandardCharsets.UTF_8);
        assertThat(body, startsWith("6\r\nstart;\r\n3\r\nc0;\r\n3\r\nc1;\r\n"));
        assertThat(body, endsWith("0\r\n\r\n"));
        assertThat(out.closed, is(true));
        assertThat(msg.getResponseHeader().getHeader("Content-Type"), is(equalTo("text/plain")));
        assertThat(msg.getResponseHeader().getHeader("Transfer-Encoding"), is(equalTo("chunked")));
        assertThat(msg.getResponseHeader().getHeader("Content-Length"), is(nullValue()));
    }

    @Test
    void shouldNotWriteEmptyChunks() throws Exception {
        // Given
        StreamPage page = new StreamPage(server, "p", "text/plain", "x", i -> "", 1, 20, 100);
        // When
        page.handleMessage(ctx, request("/p"));
        // Then
        assertThat(out.toString(StandardCharsets.UTF_8), is(equalTo("1\r\nx\r\n0\r\n\r\n")));
        assertThat(out.closed, is(true));
    }

    @Test
    void shouldUseDurationFromQuery() throws Exception {
        // Given
        StreamPage page =
                new StreamPage(server, "p", "text/plain", "", i -> "c", 1, 600_000, 600_000);
        long start = System.currentTimeMillis();
        // When
        page.handleMessage(ctx, request("/p?duration=30&interval=1"));
        // Then
        assertThat(System.currentTimeMillis() - start < 5_000, is(true));
        assertThat(out.closed, is(true));
    }

    @Test
    void shouldWriteAtMostOneChunkPerMillisecondEvenIfIntervalIsZero() throws Exception {
        // Given
        StreamPage page =
                new StreamPage(server, "p", "text/plain", "", i -> "c", 1, 600_000, 600_000);
        // When
        page.handleMessage(ctx, request("/p?duration=50&interval=0"));
        // Then
        int chunks = out.toString(StandardCharsets.UTF_8).split("1\r\nc\r\n", -1).length - 1;
        assertThat(chunks <= 50, is(true));
    }

    @Test
    void shouldStopQuietlyIfWriteFails() throws Exception {
        // Given
        OutputStream failing =
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        throw new IOException("closed");
                    }
                };
        given(ctx.streamingResponse(any())).willReturn(failing);
        StreamPage page = new StreamPage(server, "p", "text/plain", "x", i -> "c", 1, 30, 100);
        // When / Then
        page.handleMessage(ctx, request("/p"));
    }

    @Test
    void shouldNotStartStreamingOnMalformedHeader() throws Exception {
        // Given
        StreamPage page = new StreamPage(server, "p", "bad\r\ntype", "x", i -> "c", 1, 30, 100);
        // When
        page.handleMessage(ctx, request("/p"));
        // Then
        verify(ctx, never()).streamingResponse(any());
    }

    private static HttpMessage request(String path) throws Exception {
        return new HttpMessage(new HttpRequestHeader("GET " + path + " HTTP/1.1"));
    }

    private static class ClosableByteArrayOutputStream extends ByteArrayOutputStream {
        boolean closed;

        @Override
        public void close() {
            closed = true;
        }
    }
}
