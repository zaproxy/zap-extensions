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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.EventExecutorGroup;
import java.io.IOException;
import java.net.PasswordAuthentication;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.mutable.MutableInt;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InOrder;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderApache;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestHttpServer;
import org.zaproxy.addon.network.testutils.TestHttpServer.TestHttpMessageHandler;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link HttpSender} implementations. */
class HttpSenderImplUnitTest {

    private static final int INITIATOR = -1234;

    private static final String PROXY_RESPONSE = "Proxy Response";
    private static final String SERVER_RESPONSE = "Server Response";
    private static final String DEFAULT_SERVER_HEADER = "HTTP/1.1 200 OK";

    private static NioEventLoopGroup group;
    private static EventExecutorGroup mainHandlerExecutor;

    private TestHttpMessageHandler defaultHandler;
    private TestHttpServer server;
    private int serverPort;

    private HttpMessage message;

    private CookieStore globalCookieStore;
    private ConnectionOptions options;
    private ClientCertificatesOptions clientCertificatesOptions;
    private KeyStores keyStores;

    private HttpSenderImplWrapper<?> httpSender;

    @BeforeAll
    static void setupAll() throws Exception {
        group = new NioEventLoopGroup(new DefaultThreadFactory("ZAP-HttpSenderImplUnitTest"));
        mainHandlerExecutor =
                new DefaultEventExecutorGroup(
                        NettyRuntime.availableProcessors() * 2,
                        new DefaultThreadFactory("ZAP-HttpSenderImplUnitTest-Events"));
    }

    @AfterAll
    static void tearDownAll() throws Exception {
        if (group != null) {
            group.shutdownGracefully();
            group = null;
        }

        if (mainHandlerExecutor != null) {
            mainHandlerExecutor.shutdownGracefully();
            mainHandlerExecutor = null;
        }
    }

    @BeforeEach
    void setup() throws IOException {
        server = new TestHttpServer(group, mainHandlerExecutor);
        defaultHandler =
                (ctx, msg) -> {
                    msg.setResponseHeader(DEFAULT_SERVER_HEADER);
                    msg.setResponseBody(SERVER_RESPONSE);
                    msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                };
        server.setHttpMessageHandler(defaultHandler);
        serverPort = server.start(Server.ANY_PORT);

        message = createMessage("GET", "/");

        options = new ConnectionOptions();
        options.load(new ZapXmlConfiguration());
        clientCertificatesOptions = mock(ClientCertificatesOptions.class);
        keyStores = mock(KeyStores.class);
        given(clientCertificatesOptions.getKeyStores()).willReturn(keyStores);

        httpSender =
                new HttpSenderImplWrapper<>(
                        new HttpSenderApache(
                                () -> globalCookieStore, options, clientCertificatesOptions),
                        INITIATOR);
    }

    @AfterEach
    void teardown() throws IOException {
        server.close();
        httpSender.close();
    }

    @Test
    void shouldThrowWhenAddingNullHttpSenderListener() throws Exception {
        // Given
        HttpSenderListener listener = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> httpSender.addListener(listener));
    }

    @Test
    void shouldThrowWhenRemovingNullHttpSenderListener() throws Exception {
        // Given
        HttpSenderListener listener = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> httpSender.addListener(listener));
    }

    static Stream<SenderMethod> sendAndReceiveMethods() {
        return Stream.of(
                (httpSender, httpMessage) -> httpSender.sendAndReceive(httpMessage),
                (httpSender, httpMessage) -> httpSender.sendAndReceive(httpMessage, false),
                (httpSender, httpMessage) ->
                        httpSender.sendAndReceive(
                                httpMessage, HttpRequestConfig.builder().build()));
    }

    static Stream<Arguments> requestMethodsAndSendAndReceiveMethods() {
        return Stream.of(
                        "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
                        "TRACK", "XYZ")
                .flatMap(method -> sendAndReceiveMethods().map(sm -> arguments(method, sm)));
    }

    @Nested
    class Request {

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentPreservingNonAsciiCharactersInHeader(SenderMethod method)
                throws Exception {
            // Given
            HttpRequestHeader requestHeader = message.getRequestHeader();
            requestHeader.setHeader("Host", "localhost:" + serverPort);
            requestHeader.setHeader("J/ψ", " → VP");
            requestHeader.setContentLength(0);
            server.setFixedLengthMessage(79);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(equalTo(requestHeader.toString())));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldBeSentWithBodyForAnyMethod(String requestMethod, SenderMethod method)
                throws Exception {
            // Given
            String requestBody = "Request Body";
            message.getRequestHeader().setMethod(requestMethod);
            message.setRequestBody(requestBody);
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(
                            equalTo(
                                    requestMethod
                                            + " "
                                            + getServerUri("/")
                                            + " HTTP/1.1\r\n"
                                            + "Content-Length: 12\r\n"
                                            + "Host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo(requestBody)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentWithExistingHostHeaderRemainingInPlace(SenderMethod method)
                throws Exception {
            // Given
            message.getRequestHeader().setHeader("Host", "localhost:" + serverPort);
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(
                            equalTo(
                                    "GET "
                                            + getServerUri("/")
                                            + " HTTP/1.1\r\n"
                                            + "Host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "Content-Length: 0\r\n"
                                            + "\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentWithUpdatedHostHeaderRemainingInPlace(SenderMethod method)
                throws Exception {
            // Given
            message.getRequestHeader().setHeader("Host", "example.org:" + serverPort);
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(
                            equalTo(
                                    "GET "
                                            + getServerUri("/")
                                            + " HTTP/1.1\r\n"
                                            + "Host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "Content-Length: 0\r\n"
                                            + "\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentWithHostHeaderIfNotAlreadyPresent(SenderMethod method) throws Exception {
            // Given
            message.getRequestHeader().setHeader("Host", null);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(
                            equalTo(
                                    "GET "
                                            + getServerUri("/")
                                            + " HTTP/1.1\r\n"
                                            + "Host: localhost:"
                                            + serverPort
                                            + "\r\n\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentWithIncorrectContentLength(SenderMethod method) throws Exception {
            // Given
            message.getRequestHeader().setHeader("Host", "localhost:" + serverPort);
            message.getRequestHeader().setContentLength(42);
            server.setFixedLengthMessage(61);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(
                            equalTo(
                                    "GET "
                                            + getServerUri("/")
                                            + " HTTP/1.1\r\n"
                                            + "Host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "Content-Length: 42\r\n"
                                            + "\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldBeSentWithRetriesOnIoError(String requestMethod, SenderMethod method)
                throws Exception {
            // Given
            String requestBody = "Request Body";
            message.getRequestHeader().setMethod(requestMethod);
            message.setRequestBody(requestBody);
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
            int maxRetries = 5;
            httpSender.setMaxRetriesOnIOError(maxRetries);
            MutableInt counter = new MutableInt();
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        if (counter.incrementAndGet() < maxRetries) {
                            ctx.close();
                            return;
                        }
                        defaultHandler.handleMessage(ctx, msg);
                    });
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(maxRetries));
            for (HttpMessage receivedMessage : server.getReceivedMessages()) {
                assertThat(
                        receivedMessage.getRequestHeader().toString(),
                        is(
                                equalTo(
                                        requestMethod
                                                + " "
                                                + getServerUri("/")
                                                + " HTTP/1.1\r\n"
                                                + "Content-Length: 12\r\n"
                                                + "Host: localhost:"
                                                + serverPort
                                                + "\r\n"
                                                + "\r\n")));
                assertThat(receivedMessage.getRequestBody().toString(), is(equalTo(requestBody)));
            }
        }
    }

    static Stream<Arguments> chunkSizesAndSendAndReceiveMethods() {
        return Stream.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 33, 50, 66, 80, 99, 100)
                .flatMap(method -> sendAndReceiveMethods().map(sm -> arguments(method, sm)));
    }

    @Nested
    class Response {

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldHaveDataReceived(SenderMethod method) throws Exception {
            // Given
            String responseHeader =
                    "HTTP/1.1 500 Reason\r\nHeader1: HeaderValue\r\nX: y\r\nContent-Length: 13\r\n\r\n";
            String responseBody = "Response Body";
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader(responseHeader);
                        msg.setResponseBody(responseBody);
                    });
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getResponseHeader().toString(), is(equalTo(responseHeader)));
            assertThat(message.getResponseBody().toString(), is(equalTo(responseBody)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldPreserveNonAsciiCharactersInHeader(SenderMethod method) throws Exception {
            // Given
            String responseHeader = "HTTP/1.1 200 OK\r\nJ/ψ:  → VP\r\nContent-Length: 0\r\n\r\n";
            server.setHttpMessageHandler((ctx, msg) -> msg.setResponseHeader(responseHeader));
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getResponseHeader().toString(), is(equalTo(responseHeader)));
        }

        @Test
        void shouldBeDownloadedToFile(@TempDir Path dir) throws Exception {
            // Given
            Path file = Files.createTempDirectory(dir, "downloads").resolve("download");
            long size = 64_000_000L;
            server.setRawHandler(
                    (ctx, msg) -> {
                        ByteBuf out = ctx.alloc().buffer();
                        ByteBufUtil.writeAscii(
                                out, "HTTP/1.1 200 OK\r\nContent-Length: " + size + "\r\n\r\n");
                        ctx.write(out);

                        out = ctx.alloc().buffer(10);
                        ByteBufUtil.writeAscii(out, "0123456789");
                        long totalWrites = size / 10;
                        for (int i = 0; i < totalWrites; i++) {
                            ctx.write(out.retainedDuplicate());
                            if (i % 100 == 0) {
                                ctx.flush();
                            }
                        }
                        out.release();
                        ctx.writeAndFlush(Unpooled.EMPTY_BUFFER)
                                .addListener(ChannelFutureListener.CLOSE);
                    });
            // When
            httpSender.sendAndReceive(message, file);
            // Then
            assertThat(Files.size(file), is(equalTo(size)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldHaveTimingsSet(SenderMethod method) throws Exception {
            // Given
            long now = System.currentTimeMillis();
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getTimeSentMillis(), is(greaterThanOrEqualTo(now)));
            assertThat(message.getTimeElapsedMillis(), is(greaterThan(0)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeFromTargetIfRequestSent(SenderMethod method) throws Exception {
            // Given / When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.isResponseFromTargetHost(), is(equalTo(true)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeFromTargetIfRequestNotSent(SenderMethod method) throws Exception {
            // Given
            server.setHttpMessageHandler((ctx, msg) -> ctx.close());
            // When
            assertThrows(IOException.class, () -> method.sendWith(httpSender, message));
            // Then
            assertThat(server.getReceivedMessages(), is(not(empty())));
            assertThat(message.isResponseFromTargetHost(), is(equalTo(false)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldHaveContentEncodingsSetToBody() throws Exception {
            // Given
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Encoding: gzip");
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getResponseBody().getContentEncodings(), is(not(empty())));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotHaveContentEncodingsSetToBodyIfNoneInHeader() throws Exception {
            // Given / When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getResponseBody().getContentEncodings(), is(empty()));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethodsWithRedirections")
        void shouldContainFinalResponseOfFollowedRedirections(SenderMethod method)
                throws Exception {
            // Given
            int expectedMessages = 3;
            AtomicInteger requestCounter = new AtomicInteger(1);
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        int requestCount = requestCounter.getAndIncrement();
                        if (requestCount < expectedMessages) {
                            msg.setResponseHeader("HTTP/1.1 302");
                            msg.getResponseHeader()
                                    .setHeader("Location", getServerUri("/redir" + requestCount));
                        } else {
                            msg.setResponseHeader("HTTP/1.1 200");
                            msg.setResponseBody("Final Response");
                        }
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(expectedMessages));
            assertThat(
                    message.getRequestHeader().getURI().toString(), is(equalTo(getServerUri("/"))));
            assertThat(message.getResponseHeader().getStatusCode(), is(equalTo(200)));
            assertThat(message.getResponseBody().toString(), is(equalTo("Final Response")));
        }

        @Nested
        class Chunked {

            private final String RESPONSE_HEADER =
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";

            private final String RESPONSE_BODY =
                    "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n"
                            + "[...]\r"
                            + "		<script type=\"text/javascript\">/* <![CDATA[ */\n\r\n"
                            + "[...]\n"
                            + "				// some comment FOLLOWED BY TRAILING TABS:		\r"
                            + "				theLineAfterwards();\r\n";

            private Supplier<String> chunkedBodySupplier;

            @BeforeEach
            void setUp() {
                server.setHttpMessageHandler(
                        (ctx, msg) -> {
                            msg.setResponseHeader(RESPONSE_HEADER);
                            msg.setResponseBody(chunkedBodySupplier.get());
                        });
            }

            private void assertResponseNotChunked() {
                assertThat(server.getReceivedMessages(), hasSize(1));
                assertThat(
                        message.getResponseHeader().getHeader("Transfer-Encoding"),
                        is(nullValue()));
                assertThat(message.getResponseBody().toString(), is(equalTo(RESPONSE_BODY)));
                assertThat(message.getResponseHeader().getContentLength(), is(equalTo(249)));
            }

            @ParameterizedTest
            @MethodSource(
                    "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
            void shouldHaveSingleChunkRemoved(SenderMethod method) throws Exception {
                // Given
                chunkedBodySupplier =
                        () ->
                                Integer.toHexString(RESPONSE_BODY.length())
                                        + "\r\n"
                                        + RESPONSE_BODY
                                        + "\r\n0\r\n\r\n";
                // When
                method.sendWith(httpSender, message);
                // Then
                assertResponseNotChunked();
            }

            @ParameterizedTest
            @MethodSource(
                    "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#chunkSizesAndSendAndReceiveMethods")
            void shouldHaveMultipleChunksRemoved(int chunkSize, SenderMethod method)
                    throws Exception {
                // Given
                chunkedBodySupplier =
                        () -> {
                            StringBuilder strBuilder = new StringBuilder();
                            String chunkSizeHex = Integer.toHexString(chunkSize);
                            int bodyLength = RESPONSE_BODY.length();
                            int i = 0;
                            for (int max = bodyLength - chunkSize; i < max; i += chunkSize) {
                                strBuilder
                                        .append(chunkSizeHex)
                                        .append("\r\n")
                                        .append(RESPONSE_BODY, i, i + chunkSize)
                                        .append("\r\n");
                            }
                            if (i < bodyLength) {
                                strBuilder
                                        .append(Integer.toHexString(bodyLength - i))
                                        .append("\r\n")
                                        .append(RESPONSE_BODY, i, bodyLength)
                                        .append("\r\n");
                            }
                            strBuilder.append("0\r\n\r\n");
                            return strBuilder.toString();
                        };
                // When
                method.sendWith(httpSender, message);
                // Then
                assertResponseNotChunked();
            }
        }
    }

    static Stream<SenderMethod> sendAndReceiveMethodsWithRedirections() {
        return Stream.of(
                (httpSender, httpMessage) -> {
                    httpSender.setFollowRedirect(true);
                    httpSender.sendAndReceive(httpMessage);
                },
                (httpSender, httpMessage) -> httpSender.sendAndReceive(httpMessage, true),
                (httpSender, httpMessage) ->
                        httpSender.sendAndReceive(
                                httpMessage,
                                HttpRequestConfig.builder().setFollowRedirects(true).build()));
    }

    @Nested
    @Timeout(60)
    class Listeners {

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeNotifiedWhenSendAndReceive(SenderMethod method) throws Exception {
            // Given
            HttpSenderListener listener = mock(HttpSenderListener.class);
            httpSender.addListener(listener);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            verify(listener).onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            verify(listener).onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethodsWithRedirections")
        void shouldBeNotifiedOfAllFollowedRedirections(SenderMethod method) throws Exception {
            // Given
            int expectedMessages = 4;
            AtomicInteger requestCounter = new AtomicInteger(1);
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        int requestCount = requestCounter.getAndIncrement();
                        if (requestCount < expectedMessages) {
                            msg.setResponseHeader("HTTP/1.1 302");
                            msg.getResponseHeader()
                                    .setHeader("Location", getServerUri("/redir" + requestCount));
                        } else {
                            msg.setResponseHeader("HTTP/1.1 200");
                        }
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            TestHttpSenderListener listener = new TestHttpSenderListener();
            httpSender.addListener(listener);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(expectedMessages));
            List<HttpMessage> messagesNotified = listener.getMessages();
            assertThat(messagesNotified, hasSize(expectedMessages));
            assertThat(
                    messagesNotified.get(0).getRequestHeader().getURI().toString(),
                    is(equalTo(getServerUri("/redir1"))));
            assertThat(
                    messagesNotified.get(0).getResponseHeader().getStatusCode(), is(equalTo(302)));
            assertThat(
                    messagesNotified.get(1).getRequestHeader().getURI().toString(),
                    is(equalTo(getServerUri("/redir2"))));
            assertThat(
                    messagesNotified.get(1).getResponseHeader().getStatusCode(), is(equalTo(302)));
            assertThat(
                    messagesNotified.get(2).getRequestHeader().getURI().toString(),
                    is(equalTo(getServerUri("/redir3"))));
            assertThat(
                    messagesNotified.get(2).getResponseHeader().getStatusCode(), is(equalTo(200)));
            assertThat(
                    messagesNotified.get(3).getRequestHeader().getURI().toString(),
                    is(equalTo(getServerUri("/"))));
            assertThat(
                    messagesNotified.get(3).getResponseHeader().getStatusCode(), is(equalTo(200)));
        }

        @Test
        void shouldNotBeNotifiedWhenNotificationIsDisabled() throws Exception {
            // Given
            HttpSenderListener listener = mock(HttpSenderListener.class);
            httpSender.addListener(listener);
            HttpRequestConfig requestConfig =
                    HttpRequestConfig.builder().setNotifyListeners(false).build();
            // When
            httpSender.sendAndReceive(message, requestConfig);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            verifyNoInteractions(listener);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeNotifiedInListenerOrder(SenderMethod method) throws Exception {
            // Given
            HttpSenderListener listener1 = mock(HttpSenderListener.class);
            given(listener1.getListenerOrder()).willReturn(1);
            httpSender.addListener(listener1);
            HttpSenderListener listener2 = mock(HttpSenderListener.class);
            given(listener2.getListenerOrder()).willReturn(2);
            httpSender.addListener(listener2);
            HttpSenderListener listener3 = mock(HttpSenderListener.class);
            given(listener3.getListenerOrder()).willReturn(-1);
            httpSender.addListener(listener3);
            HttpSenderListener listener4 = mock(HttpSenderListener.class);
            given(listener4.getListenerOrder()).willReturn(2);
            httpSender.addListener(listener4);
            InOrder inOrder = inOrder(listener1, listener2, listener3, listener4);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            inOrder.verify(listener3).onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener1).onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener2).onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener4).onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener3)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener1)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener2)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            inOrder.verify(listener4)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldContinueToBeNotifiedAfterListenerExceptions(SenderMethod method)
                throws Exception {
            // Given
            HttpSenderListener listener = mock(HttpSenderListener.class);
            doThrow(NullPointerException.class)
                    .when(listener)
                    .onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            doThrow(NullPointerException.class)
                    .when(listener)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            httpSender.addListener(listener);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            verify(listener, times(2))
                    .onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            verify(listener, times(2))
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldContinueToBeNotifiedAfterOtherListenerExceptions(SenderMethod method)
                throws Exception {
            // Given
            HttpSenderListener listener1 = mock(HttpSenderListener.class);
            doThrow(NullPointerException.class)
                    .when(listener1)
                    .onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            doThrow(NullPointerException.class)
                    .when(listener1)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            given(listener1.getListenerOrder()).willReturn(1);
            httpSender.addListener(listener1);
            HttpSenderListener listener2 = mock(HttpSenderListener.class);
            given(listener2.getListenerOrder()).willReturn(2);
            httpSender.addListener(listener2);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            verify(listener2, times(2))
                    .onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            verify(listener2, times(2))
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeNotifiedConcurrentlyFromSameHttpSender(SenderMethod method) throws Exception {
            // Given
            CyclicBarrier barrier = new CyclicBarrier(3);
            TestHttpSenderListener listener =
                    new TestHttpSenderListener(
                            (messages, message, initiator, sender) -> {
                                messages.add(message);
                                barrier.await();
                            });
            httpSender.addListener(listener);
            HttpMessage message2 = createMessage("GET", "/");
            ForkJoinPool pool = new ForkJoinPool(2);
            // When
            pool.submit(
                    () -> {
                        method.sendWith(httpSender, message);
                        return null;
                    });
            pool.submit(
                    () -> {
                        method.sendWith(httpSender, message2);
                        return null;
                    });
            // Then
            barrier.await();
            pool.shutdown();
            assertThat(barrier.isBroken(), is(equalTo(false)));
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(
                    listener.getMessages(),
                    containsInAnyOrder(sameInstance(message), sameInstance(message2)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeNotifiedConcurrentlyFromDifferentHttpSenders(SenderMethod method)
                throws Exception {
            // Given
            CyclicBarrier barrier = new CyclicBarrier(3);
            TestHttpSenderListener listener =
                    new TestHttpSenderListener(
                            (messages, message, initiator, sender) -> {
                                messages.add(message);
                                barrier.await();
                            });
            httpSender.addListener(listener);
            HttpSenderImplWrapper<?> httpSender2 =
                    new HttpSenderImplWrapper<>(
                            new HttpSenderApache(
                                    () -> globalCookieStore, options, clientCertificatesOptions),
                            INITIATOR);
            httpSender2.addListener(listener);
            HttpMessage message2 = createMessage("GET", "/");
            ForkJoinPool pool = new ForkJoinPool(2);
            // When
            pool.submit(
                    () -> {
                        method.sendWith(httpSender, message);
                        return null;
                    });
            pool.submit(
                    () -> {
                        method.sendWith(httpSender2, message2);
                        return null;
                    });
            // Then
            barrier.await();
            pool.shutdown();
            httpSender2.close();
            assertThat(barrier.isBroken(), is(equalTo(false)));
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(
                    listener.getMessages(),
                    containsInAnyOrder(sameInstance(message), sameInstance(message2)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeNotifiedForMessagesSentFromThemselves(SenderMethod method)
                throws Exception {
            // Given
            TestHttpSenderListener listener =
                    new TestHttpSenderListener(
                            (messages, message, initiator, sender) -> {
                                messages.add(message);
                                sender.sendAndReceive(message.cloneRequest());
                            });
            httpSender.addListener(listener);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(listener.getMessages(), hasSize(1));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeAbleToAddOtherListenersWhenNotifiedOfRequest(SenderMethod method)
                throws Exception {
            // Given
            HttpSenderListener listener1 = mock(HttpSenderListener.class);
            HttpSenderListener listener2 = mock(HttpSenderListener.class);
            doAnswer(
                            invocation -> {
                                httpSender.addListener(listener2);
                                return null;
                            })
                    .when(listener1)
                    .onHttpRequestSend(message, INITIATOR, httpSender.getParent());
            httpSender.addListener(listener1);
            // When / Then
            assertThrows(
                    ConcurrentModificationException.class,
                    () -> method.sendWith(httpSender, message));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeAbleToAddOtherListenersWhenNotifiedOfResponse(SenderMethod method)
                throws Exception {
            // Given
            HttpSenderListener listener1 = mock(HttpSenderListener.class);
            HttpSenderListener listener2 = mock(HttpSenderListener.class);
            doAnswer(
                            invocation -> {
                                httpSender.addListener(listener2);
                                return null;
                            })
                    .when(listener1)
                    .onHttpResponseReceive(message, INITIATOR, httpSender.getParent());
            httpSender.addListener(listener1);
            // When / Then
            assertThrows(
                    ConcurrentModificationException.class,
                    () -> method.sendWith(httpSender, message));
        }
    }

    @Nested
    class Proxy {

        private TestHttpServer proxy;
        private int proxyPort;

        @BeforeEach
        void setup() throws IOException {
            proxy = new TestHttpServer(group, mainHandlerExecutor);
            proxy.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader(DEFAULT_SERVER_HEADER);
                        msg.setResponseBody(PROXY_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            proxyPort = proxy.start(Server.ANY_PORT);
        }

        @AfterEach
        void teardown() throws IOException {
            proxy.close();
        }

        @Test
        void shouldProxyIfEnabled() throws Exception {
            // Given
            configOptionsWithProxy("localhost", proxyPort);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertThat(message.getResponseBody().toString(), is(equalTo(PROXY_RESPONSE)));
        }

        @Test
        void shouldNotProxyIfDisabled() throws Exception {
            // Given
            configOptionsWithProxy("localhost", proxyPort);
            options.setHttpProxyEnabled(false);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(0));
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(
                    server.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(message.getResponseBody().toString(), is(equalTo(SERVER_RESPONSE)));
        }

        @Test
        void shouldNotAuthenticateToProxyIfAuthDisabled() throws Exception {
            // Given
            proxy.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader(
                                "HTTP/1.1 407\r\nProxy-Authenticate: Basic realm=\"\"\r\n");
                        msg.setResponseBody(PROXY_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            configOptionsWithProxy("localhost", proxyPort);
            options.setHttpProxyAuthEnabled(false);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader("Proxy-Authorization"),
                    is(nullValue()));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertThat(message.getResponseBody().toString(), is(equalTo(PROXY_RESPONSE)));
        }

        @Test
        void shouldBasicAuthenticateToProxy() throws Exception {
            // Given
            String authRealm = "SomeRealm";
            AtomicBoolean challenged = new AtomicBoolean();
            proxy.setHttpMessageHandler(
                    (ctx, msg) -> {
                        if (challenged.compareAndSet(false, true)) {
                            msg.setResponseHeader(
                                    "HTTP/1.1 407\r\nProxy-Authenticate: Basic realm=\""
                                            + authRealm
                                            + "\"\r\n");
                            msg.setResponseBody(PROXY_RESPONSE);
                            msg.getResponseHeader()
                                    .setContentLength(msg.getResponseBody().length());
                            return;
                        }

                        msg.setResponseHeader("HTTP/1.1 200\r\n");
                        msg.setResponseBody(SERVER_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            configOptionsWithProxy("localhost", proxyPort, authRealm);
            // When
            httpSender.sendAndReceive(message);
            // Then

            assertThat(proxy.getReceivedMessages(), hasSize(2));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader("Proxy-Authorization"),
                    is(nullValue()));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader("Proxy-Authorization"),
                    is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
            assertThat(
                    proxy.getReceivedMessages().get(1).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertThat(message.getResponseBody().toString(), is(equalTo(SERVER_RESPONSE)));
        }

        @Test
        void shouldNotBasicAuthenticateToProxyIfRealmMismatch() throws Exception {
            // Given
            proxy.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader(
                                "HTTP/1.1 407\r\nProxy-Authenticate: Basic realm=\"SomeRealm\"\r\n");
                        msg.setResponseBody(PROXY_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            configOptionsWithProxy("localhost", proxyPort, "NotSomeRealm");
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader("Proxy-Authorization"),
                    is(nullValue()));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertThat(message.getResponseBody().toString(), is(equalTo(PROXY_RESPONSE)));
        }

        private void configOptionsWithProxy(String host, int port) {
            configOptionsWithProxy(host, port, "");
        }

        private void configOptionsWithProxy(String host, int port, String realm) {
            options.setHttpProxy(
                    new HttpProxy(
                            host,
                            port,
                            realm,
                            new PasswordAuthentication("username", "password".toCharArray())));
            options.setHttpProxyEnabled(true);
            options.setHttpProxyAuthEnabled(true);
        }
    }

    private HttpMessage createMessage(String method, String path) {
        try {
            URI uri = new URI(getServerUri(path), true);
            HttpRequestHeader requestHeader =
                    new HttpRequestHeader(method + " " + uri + " HTTP/1.1");
            return new HttpMessage(requestHeader);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getServerUri(String path) {
        return "http://localhost:" + serverPort + path;
    }

    private static class TestHttpSenderListener implements HttpSenderListener {

        private final List<HttpMessage> messages;
        private final HttpMessageProcessor messageProcessor;

        TestHttpSenderListener() {
            this((messages, message, initiator, sender) -> messages.add(message.cloneAll()));
        }

        TestHttpSenderListener(HttpMessageProcessor messageProcessor) {
            this.messages = Collections.synchronizedList(new ArrayList<>());
            this.messageProcessor = messageProcessor;
        }

        List<HttpMessage> getMessages() {
            return messages;
        }

        @Override
        public int getListenerOrder() {
            return 0;
        }

        @Override
        public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {}

        @Override
        public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
            try {
                messageProcessor.process(messages, msg, initiator, sender);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private interface HttpMessageProcessor {
        void process(
                List<HttpMessage> messages, HttpMessage message, int initiator, HttpSender sender)
                throws Exception;
    }

    private interface SenderMethod {
        void sendWith(HttpSenderImplWrapper<?> httpSender, HttpMessage message) throws IOException;
    }
}
