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
package org.zaproxy.addon.network.internal.server.http;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.codec.HttpRequestDecoder;
import org.zaproxy.addon.network.internal.codec.HttpResponseEncoder;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** Unit test for {@link MainServerHandler}. */
class MainServerHandlerUnitTest {

    private static final InetSocketAddress SENDER_ADDRESS =
            new InetSocketAddress("127.0.0.1", 1234);

    private List<Throwable> exceptionsThrown;

    private TestHttpMessageHandler handler1;
    private TestHttpMessageHandler handler2;
    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        exceptionsThrown = new ArrayList<>();

        handler1 = new TestHttpMessageHandler();
        handler2 = new TestHttpMessageHandler();
        channel =
                new EmbeddedChannel(
                        new HttpRequestDecoder(),
                        HttpResponseEncoder.getInstance(),
                        new MainServerHandler(Arrays.asList(handler1, handler2)),
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                fail("The message should not be passed to following handler.");
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                exceptionsThrown.add(cause);
                            }
                        });
        channel.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
        channel.attr(ChannelAttributes.REMOTE_ADDRESS).set(SENDER_ADDRESS);
        channel.attr(ChannelAttributes.RECURSIVE_MESSAGE).set(Boolean.FALSE);
        channel.attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.FALSE);
    }

    @Test
    void shouldThrowIfHandlersListIsNull() {
        // Given
        List<HttpMessageHandler> handlers = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> new MainServerHandler(handlers));
    }

    @Test
    void shouldThrowExceptionInDecodedHttpMessage() {
        // Given
        String request = "MalformedRequest HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(1));
    }

    @Test
    void shouldNotBeProcessingAfterHandling() {
        // Given
        String request = "GET / HTTP/1.1\\r\\n\\r\\n";
        // When
        written(request);
        // Then
        assertProcessing(false);
    }

    @Test
    void shouldNotifyAllHandlersForRequestAndResponse() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(2);
        handler1.assertFromClient(0, true);
        handler1.assertFromClient(1, false);
        handler2.assertCalled(2);
        handler2.assertFromClient(0, true);
        handler2.assertFromClient(1, false);
    }

    @Test
    void shouldWriteEmptyResponseIfNoHandlerSetOne() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        // When
        written(request);
        // Then
        assertResponse("HTTP/1.0 0\r\n\r\n");
    }

    @Test
    void shouldWriteResponseOfHandlers() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200 OK"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertResponse("HTTP/1.1 200 OK\r\n\r\n");
    }

    @Test
    void shouldWriteResponseOfLastHandlerThatSetOne() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200 OK"));
        handler2.addAction(
                0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200 OK from last handler"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertResponse("HTTP/1.1 200 OK from last handler\r\n\r\n");
    }

    @Test
    void shouldNotNotifyFollowingHandlersOfRequestIfOverridden() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> ctx.overridden());
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(1);
        handler2.assertCalled(0);
    }

    @Test
    void shouldNotNotifyFollowingHandlersOfResponseIfOverridden() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(1, (ctx, msg) -> ctx.overridden());
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(2);
        handler2.assertCalled(1);
        handler2.assertFromClient(0, true);
    }

    @Test
    void shouldNotNotifyFollowingHandlersOfRequestIfClose() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> ctx.close());
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        handler1.assertCalled(1);
        handler2.assertCalled(0);
    }

    @Test
    void shouldNotNotifyFollowingHandlersOfResponseIfClose() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(1, (ctx, msg) -> ctx.close());
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        handler1.assertCalled(2);
        handler2.assertCalled(1);
        handler2.assertFromClient(0, true);
    }

    @Test
    void shouldNotFailToNotifyFollowingHandlerIfExceptionThrown() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0,
                (ctx, msg) -> {
                    throw new TestException();
                });
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(2);
        handler2.assertCalled(2);
    }

    @Test
    void shouldStillOverrideIfExceptionThrown() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0,
                (ctx, msg) -> {
                    ctx.overridden();
                    throw new TestException();
                });
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(1);
        handler2.assertCalled(0);
    }

    @Test
    void shouldStillCloseIfExceptionThrown() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0,
                (ctx, msg) -> {
                    ctx.close();
                    throw new TestException();
                });
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(1);
        handler2.assertCalled(0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.0", "1.1"})
    void shouldNotCloseChannelForConnectRequest(String httpVersion) {
        // Given
        String request = "CONNECT example.org:443 HTTP/" + httpVersion + "\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(true);
        assertResponse("HTTP/1.1 200\r\n\r\n");
    }

    @Test
    void shouldNotCloseChannelForHttp11ResponseByDefault() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(true);
        assertResponse("HTTP/1.1 200\r\n\r\n");
    }

    @Test
    void shouldCloseChannelForHttp11ResponseIfCloseHeader() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200\r\nConnection: close"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        assertResponse("HTTP/1.1 200\r\nConnection: close\r\n\r\n");
    }

    @Test
    void shouldCloseChannelForHttp10ResponseByDefault() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.0 200"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        assertResponse("HTTP/1.0 200\r\n\r\n");
    }

    @Test
    void shouldCloseChannelForHttp10ResponseIfKeepAliveHeader() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.0 200\r\nConnection: keep-alive"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(true);
        assertResponse("HTTP/1.0 200\r\nConnection: keep-alive\r\n\r\n");
    }

    @Test
    void shouldCloseChannelForRequestIfCloseHeader() throws Exception {
        // Given
        String request = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        handler1.addAction(
                0, (ctx, msg) -> msg.setResponseHeader("HTTP/1.1 200\r\nConnection: keep-alive"));
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        assertResponse("HTTP/1.1 200\r\nConnection: keep-alive\r\n\r\n");
    }

    @Test
    void shouldCloseChannelIfUndeterminedResponseBodyLength() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        handler1.addAction(
                0,
                (ctx, msg) -> {
                    msg.setResponseHeader("HTTP/1.1 200");
                    msg.setResponseBody("Not empty body");
                });
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        assertChannelActive(false);
        assertResponse("HTTP/1.1 200\r\n\r\nNot empty body");
    }

    @Test
    void shouldNotBeRecursiveIfNotSet() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        channel.attr(ChannelAttributes.RECURSIVE_MESSAGE).set(Boolean.FALSE);
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(2);
        handler1.assertRecursive(0, false);
        handler1.assertRecursive(1, false);
        handler2.assertCalled(2);
        handler2.assertRecursive(0, false);
        handler2.assertRecursive(1, false);
    }

    @Test
    void shouldBeRecursiveIfSet() {
        // Given
        String request = "GET / HTTP/1.1\r\n\r\n";
        channel.attr(ChannelAttributes.RECURSIVE_MESSAGE).set(Boolean.TRUE);
        // When
        written(request);
        // Then
        assertThat(exceptionsThrown, hasSize(0));
        handler1.assertCalled(2);
        handler1.assertRecursive(0, true);
        handler1.assertRecursive(1, true);
        handler2.assertCalled(2);
        handler2.assertRecursive(0, true);
        handler2.assertRecursive(1, true);
    }

    private void assertChannelActive(boolean state) {
        assertThat(channel.isActive(), is(equalTo(state)));
    }

    private void assertResponse(String response) {
        ByteBuf encoded = channel.readOutbound();
        assertNotNull(encoded);
        assertThat(encoded.toString(StandardCharsets.US_ASCII), is(equalTo(response)));
    }

    private class TestHttpMessageHandler implements HttpMessageHandler {

        private int called;
        private List<ContextState> ctxs = new ArrayList<>();
        private List<HttpMessage> msgs = new ArrayList<>();
        private Map<Integer, Action> actions = new HashMap<>();

        void addAction(int i, Action action) {
            actions.put(i, action);
        }

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            called++;
            ctxs.add(new ContextState(ctx));
            msgs.add(msg.cloneAll());

            try {
                actions.getOrDefault(called - 1, (a, b) -> {}).accept(ctx, msg);

                assertProcessing(true);
            } catch (TestException e) {
                throw e;
            } catch (Throwable e) {
                exceptionsThrown.add(e);
            }
        }

        void assertCalled(int times) {
            assertThat(called, is(equalTo(times)));
        }

        public void assertRecursive(int i, boolean recursive) {
            ContextState ctx = ctxs.get(i);
            assertThat(ctx.recursive, is(equalTo(recursive)));
        }

        void assertFromClient(int i, boolean fromClient) {
            ContextState ctx = ctxs.get(i);
            assertThat(ctx.fromClient, is(equalTo(fromClient)));
        }
    }

    private static class ContextState {

        boolean recursive;
        boolean fromClient;

        ContextState(HttpMessageHandlerContext ctx) {
            this.recursive = ctx.isRecursive();
            this.fromClient = ctx.isFromClient();
        }
    }

    interface Action {
        void accept(HttpMessageHandlerContext ctx, HttpMessage msg) throws Exception;
    }

    private static class TestException extends RuntimeException {

        private static final long serialVersionUID = 1L;
    }

    private void assertProcessing(boolean state) {
        Boolean expectedState = Boolean.valueOf(state);
        Boolean actualState = channel.attr(ChannelAttributes.PROCESSING_MESSAGE).get();
        assertTrue(expectedState.equals(actualState));
    }

    private void written(String content) {
        ByteBuf buf = Unpooled.copiedBuffer(content, StandardCharsets.US_ASCII);
        assertThat(channel.writeInbound(buf), is(equalTo(false)));
    }
}
