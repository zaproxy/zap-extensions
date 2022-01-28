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
package org.zaproxy.addon.network.internal.handlers;

import static java.time.Duration.ofMillis;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.AbstractChannel;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opentest4j.AssertionFailedError;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/** Unit test for {@link LegacySocketAdapter}. */
@Timeout(5)
class LegacySocketAdapterUnitTest {

    private EmbeddedChannel inboundChannel;
    private ChannelPipeline pipeline;

    private LegacySocketAdapter socketAdapter;

    @BeforeEach
    void setUp() {
        inboundChannel = new EmbeddedChannel();
        setUpChannel(inboundChannel);
    }

    private void setUpChannel(AbstractChannel channel) {
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        pipeline = channel.pipeline();
        pipeline.addLast("filler 0", new DummyHandler())
                .addLast(TlsProtocolHandler.TLS_HANDLER_NAME, new DummyHandler())
                .addLast("timeout", new DummyHandler())
                .addLast("filler 1", new DummyHandler())
                .addLast("filler 2", new DummyHandler());
    }

    @Test
    void shouldThrowIfNullChannel() throws Exception {
        // Given
        Channel channel = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new LegacySocketAdapter(channel));
    }

    @Test
    void shouldThrowIfTlsUpgradedAttributeNotPresent() throws Exception {
        // Given
        inboundChannel = new EmbeddedChannel();
        inboundChannel.pipeline().addLast("timeout", new DummyHandler());
        // When /Then
        assertThrows(NullPointerException.class, () -> new LegacySocketAdapter(inboundChannel));
    }

    @Test
    void shouldRemoveTimeoutHandler() throws Exception {
        // Given
        inboundChannel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        // When
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // Then
        assertThat(pipeline.names(), not(contains("timeout")));
    }

    @Test
    void shouldThrowIfTimeoutHandlerNotPresent() throws Exception {
        // Given
        inboundChannel = new EmbeddedChannel();
        inboundChannel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        inboundChannel.pipeline().addLast("exception", new DummyHandler());
        // When / Then
        Exception exception =
                assertThrows(
                        NoSuchElementException.class,
                        () -> new LegacySocketAdapter(inboundChannel));
        assertThat(exception.getMessage(), containsString("timeout"));
    }

    @Test
    void shouldAddItselfAsFirstHandlerIfNotTlsUpgraded() throws Exception {
        // Given
        inboundChannel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        // When
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // Then
        assertThat(
                pipeline.names(),
                containsInRelativeOrder(LegacySocketAdapter.HANDLER_NAME, "filler 0"));
    }

    @Test
    void shouldAddItselfAfterTlsHandlerIfTlsUpgraded() throws Exception {
        // Given
        inboundChannel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.TRUE);
        // When
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // Then
        assertThat(
                pipeline.names(),
                containsInRelativeOrder(
                        TlsProtocolHandler.TLS_HANDLER_NAME, LegacySocketAdapter.HANDLER_NAME));
    }

    @Test
    void shouldThrowIfTlsUpgradedAndNoTlsHandlerPresent() throws Exception {
        // Given
        inboundChannel = new EmbeddedChannel();
        inboundChannel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.TRUE);
        inboundChannel.pipeline().addLast("timeout", new DummyHandler());
        // When / Then
        Exception exception =
                assertThrows(
                        NoSuchElementException.class,
                        () -> new LegacySocketAdapter(inboundChannel));
        assertThat(exception.getMessage(), containsString(TlsProtocolHandler.TLS_HANDLER_NAME));
    }

    @Test
    void shouldProvideSocket() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        Socket socket = socketAdapter.getSocket();
        // Then
        assertThat(socket, is(notNullValue()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetTcpNoDelayThroughTheSocket(boolean value) throws Exception {
        // Given
        AbstractChannel inboundChannel = new NioSocketChannel();
        setUpChannel(inboundChannel);
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        Socket socket = socketAdapter.getSocket();
        // When
        socket.setTcpNoDelay(value);
        // Then
        assertThat(
                inboundChannel.config().getOption(ChannelOption.TCP_NODELAY), is(equalTo(value)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetKeepAliveThroughTheSocket(boolean value) throws Exception {
        // Given
        AbstractChannel inboundChannel = new NioSocketChannel();
        setUpChannel(inboundChannel);
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        Socket socket = socketAdapter.getSocket();
        // When
        socket.setKeepAlive(value);
        // Then
        assertThat(
                inboundChannel.config().getOption(ChannelOption.SO_KEEPALIVE), is(equalTo(value)));
    }

    @Test
    void shouldReportSocketNotClosedWhenChannelActive() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        inboundChannel.isActive();
        // When
        boolean closed = socketAdapter.getSocket().isClosed();
        // Then
        assertThat(closed, is(equalTo(false)));
    }

    @Test
    void shouldReportSocketClosedWhenChannelInactive() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        inboundChannel.close();
        boolean closed = socketAdapter.getSocket().isClosed();
        // Then
        assertThat(closed, is(equalTo(true)));
    }

    @Test
    void shouldReportSocketConnected() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        boolean connected = socketAdapter.getSocket().isConnected();
        // Then
        assertThat(connected, is(equalTo(true)));
    }

    @Test
    void shouldReadWaitingForMoreDataFromInputStream() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[1];
        // When
        AssertionError error =
                assertThrows(
                        AssertionFailedError.class,
                        () ->
                                assertTimeoutPreemptively(
                                        ofMillis(250),
                                        () -> {
                                            socketAdapter
                                                    .getSocket()
                                                    .getInputStream()
                                                    .read(bytes, 0, 1);
                                        }));
        // Then
        assertThat(error.getMessage(), containsString("timed out"));
    }

    @Test
    void shouldReadAvailableDataFromInputStream() throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[11];
        // When
        written(data);
        int bytesRead = socketAdapter.getSocket().getInputStream().read(bytes, 0, 11);
        // Then
        assertThat(bytesRead, is(equalTo(11)));
        assertThat(new String(bytes, StandardCharsets.US_ASCII), is(equalTo(data)));
    }

    @Test
    void shouldReadWholeWrittenChunksFromInputStream() throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[11];
        // When
        written(data.substring(0, 5));
        written(data.substring(5, 11));
        int bytesRead = socketAdapter.getSocket().getInputStream().read(bytes, 0, 11);
        // Then
        assertThat(bytesRead, is(equalTo(11)));
        assertThat(new String(bytes, StandardCharsets.US_ASCII), is(equalTo(data)));
    }

    @Test
    void shouldPartiallyReadWrittenChunksFromInputStream() throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[11];
        // When
        written(data.substring(0, 2));
        written(data.substring(2, 4));
        written(data.substring(4, 7));
        written(data.substring(7, 11));
        int bytesRead1 = socketAdapter.getSocket().getInputStream().read(bytes, 0, 5);
        int bytesRead2 = socketAdapter.getSocket().getInputStream().read(bytes, 5, 11);
        // Then
        assertThat(bytesRead1, is(equalTo(5)));
        assertThat(bytesRead2, is(equalTo(6)));
        assertThat(new String(bytes, StandardCharsets.US_ASCII), is(equalTo(data)));
    }

    @Test
    void shouldBlockForMoreDataAfterPartiallyReadingWholeWrittenChunksFromInputStream()
            throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[11];
        // When
        written(data.substring(0, 2));
        written(data.substring(2, 4));
        written(data.substring(4, 7));
        written(data.substring(7, 11));
        int bytesRead1 = socketAdapter.getSocket().getInputStream().read(bytes, 0, 5);
        int bytesRead2 = socketAdapter.getSocket().getInputStream().read(bytes, 5, 11);
        // Then
        AssertionError error =
                assertThrows(
                        AssertionFailedError.class,
                        () ->
                                assertTimeoutPreemptively(
                                        ofMillis(250),
                                        () -> {
                                            socketAdapter
                                                    .getSocket()
                                                    .getInputStream()
                                                    .read(bytes, 11, 50);
                                        }));
        assertThat(error.getMessage(), containsString("timed out"));
        assertThat(bytesRead1, is(equalTo(5)));
        assertThat(bytesRead2, is(equalTo(6)));
        assertThat(new String(bytes, StandardCharsets.US_ASCII), is(equalTo(data)));
    }

    @Test
    void shouldReadNegativeOneIfInterruptedFromInputStream() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[1];
        // When
        Thread.currentThread().interrupt();
        int bytesRead = socketAdapter.getSocket().getInputStream().read(bytes, 0, 1);
        // Then
        assertThat(bytesRead, is(equalTo(-1)));
    }

    @Test
    void shouldReadNegativeOneIfChannelInactiveFromInputStream() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = new byte[1];
        // When
        inboundChannel.close();
        int bytesRead = socketAdapter.getSocket().getInputStream().read(bytes, 0, 1);
        // Then
        assertThat(bytesRead, is(equalTo(-1)));
    }

    @Test
    void shouldThrowIfTryingToUseOneByteRead() throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        written(data);
        // Then
        assertThrows(IOException.class, () -> socketAdapter.getSocket().getInputStream().read());
    }

    @Test
    void shouldCloseChannelOnInputStreamClose() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        socketAdapter.getSocket().getInputStream().close();
        // Then
        assertThat(inboundChannel.isActive(), is(equalTo(false)));
    }

    @Test
    void shouldWriteFromOutputStream() throws Exception {
        // Given
        String data = "Socket data";
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte[] bytes = data.getBytes(StandardCharsets.US_ASCII);
        // When
        socketAdapter.getSocket().getOutputStream().write(bytes);
        // Then
        ByteBuf buf = inboundChannel.readOutbound();
        assertThat(buf, is(notNullValue()));
        assertThat(buf.toString(StandardCharsets.US_ASCII), is(equalTo(data)));
        assertThat(buf.release(), is(equalTo(true)));
    }

    @Test
    void shouldThrowIfTryingToUseOneByteWrite() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        byte data = 0x01;
        // When / Then
        assertThrows(
                IOException.class, () -> socketAdapter.getSocket().getOutputStream().write(data));
    }

    @Test
    void shouldCloseChannelOnOutputStreamClose() throws Exception {
        // Given
        socketAdapter = new LegacySocketAdapter(inboundChannel);
        // When
        socketAdapter.getSocket().getOutputStream().close();
        // Then
        assertThat(inboundChannel.isActive(), is(equalTo(false)));
    }

    private void written(String content) {
        ByteBuf buf = Unpooled.copiedBuffer(content, StandardCharsets.US_ASCII);
        assertThat(inboundChannel.writeInbound(buf), is(equalTo(false)));
    }

    private static class DummyHandler extends SimpleChannelInboundHandler<Object> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {}
    }
}
