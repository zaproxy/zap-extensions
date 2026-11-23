/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.server.http;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link ResponseStream}. */
class ResponseStreamUnitTest {

    private EmbeddedChannel channel;
    private ResponseStream stream;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel();
        stream = new ResponseStream(channel);
    }

    @Test
    void shouldThrowOnNullChannel() {
        assertThrows(NullPointerException.class, () -> new ResponseStream(null));
    }

    @Test
    void shouldWriteBytesAsIs() throws Exception {
        // When
        stream.write("abc".getBytes(StandardCharsets.US_ASCII));
        stream.write(new byte[0]);
        stream.write('d');
        stream.write("abcdef".getBytes(StandardCharsets.US_ASCII), 2, 3);
        // Then
        assertThat(outbound(), is(equalTo("abc")));
        assertThat(outbound(), is(equalTo("d")));
        assertThat(outbound(), is(equalTo("cde")));
        assertThat(channel.readOutbound(), is(nullValue()));
    }

    @Test
    void shouldFailToWriteInvalidRange() {
        assertThrows(IndexOutOfBoundsException.class, () -> stream.write(new byte[2], 1, 2));
    }

    @Test
    void shouldCloseChannelOnClose() throws Exception {
        // When
        stream.close();
        stream.close();
        // Then
        assertThat(stream.isClosed(), is(true));
        assertThat(channel.readOutbound(), is(nullValue()));
        assertThat(channel.isActive(), is(false));
    }

    @Test
    void shouldFailToWriteAfterClose() throws Exception {
        // Given
        stream.close();
        // When / Then
        assertThrows(IOException.class, () -> stream.write('a'));
    }

    @Test
    void shouldFailToWriteIfChannelClosed() {
        // Given
        channel.close();
        // When / Then
        assertThrows(IOException.class, () -> stream.write('a'));
    }

    @Test
    void shouldFailToWriteIfWriteFails() {
        // Given
        channel = failingChannel();
        stream = new ResponseStream(channel);
        // When / Then
        assertThrows(IOException.class, () -> stream.write('a'));
    }

    private static EmbeddedChannel failingChannel() {
        return new EmbeddedChannel(
                new ChannelOutboundHandlerAdapter() {
                    @Override
                    public void write(
                            ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
                        ReferenceCountUtil.release(msg);
                        promise.setFailure(new IOException("failed"));
                    }
                });
    }

    private String outbound() {
        ByteBuf buf = channel.readOutbound();
        return buf.toString(StandardCharsets.US_ASCII);
    }
}
