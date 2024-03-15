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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
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
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.apache.commons.httpclient.HttpState;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.auth.AuthScope;
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
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.common.HttpProxy;
import org.zaproxy.addon.network.common.ZapSocketTimeoutException;
import org.zaproxy.addon.network.common.ZapUnknownHostException;
import org.zaproxy.addon.network.internal.client.apachev5.HttpSenderApache;
import org.zaproxy.addon.network.internal.ratelimit.RateLimiter;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestHttpServer;
import org.zaproxy.addon.network.testutils.TestHttpServer.TestHttpMessageHandler;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;
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

    private LegacyProxyListenerHandler legacyProxyListenerHandler;

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

        legacyProxyListenerHandler = mock(LegacyProxyListenerHandler.class);

        httpSender =
                new HttpSenderImplWrapper<>(
                        new HttpSenderApache(
                                () -> globalCookieStore,
                                options,
                                clientCertificatesOptions,
                                () -> legacyProxyListenerHandler),
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

    static Stream<Arguments> httpVersionsAndSendAndReceiveMethods() {
        return Stream.of(
                        "HTTP/0.9",
                        "HTTP/1.0",
                        "HTTP/1.1",
                        "HTTP/1.2",
                        "HTTP/2.0",
                        "HTTP/3.0",
                        "HTTP/4.5")
                .flatMap(method -> sendAndReceiveMethods().map(sm -> arguments(method, sm)));
    }

    static Stream<Arguments> noBodyKeepAliveResponseAndSendAndReceiveMethods() {
        return Stream.of("1.0", "1.1")
                .map(version -> "HTTP/" + version + " 200 OK\r\nconnection: keep-alive\r\n\r\n")
                .flatMap(response -> sendAndReceiveMethods().map(sm -> arguments(response, sm)));
    }

    static Stream<Arguments> emptyKeepAliveResponseAndSendAndReceiveMethods() {
        return Stream.of("1.0", "1.1")
                .map(
                        version ->
                                "HTTP/"
                                        + version
                                        + " 200 OK\r\ncontent-length: 0\r\nconnection: keep-alive\r\n\r\n")
                .flatMap(response -> sendAndReceiveMethods().map(sm -> arguments(response, sm)));
    }

    @Nested
    class Request {

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeThrottledForCfuInitiator(SenderMethod method) throws Exception {
            // Given
            httpSender.setInitiator(BaseHttpSender.CHECK_FOR_UPDATES_INITIATOR);
            HttpRequestHeader requestHeader = message.getRequestHeader();
            requestHeader.setHeader("Host", "localhost:" + serverPort);
            requestHeader.setContentLength(0);
            RateLimiter rateLimiter = mock(RateLimiter.class);
            httpSender.setRateLimiter(rateLimiter);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(equalTo(requestHeader.toString())));
            verify(rateLimiter, times(0)).throttle(any(), anyInt());
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeThrottledForNonCfuInitiator(SenderMethod method) throws Exception {
            // Given
            HttpRequestHeader requestHeader = message.getRequestHeader();
            requestHeader.setHeader("Host", "localhost:" + serverPort);
            requestHeader.setContentLength(0);
            RateLimiter rateLimiter = mock(RateLimiter.class);
            httpSender.setRateLimiter(rateLimiter);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(equalTo(requestHeader.toString())));
            verify(rateLimiter).throttle(message, INITIATOR);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldThrowZapUnknownHostExceptionIfHostUnknown(SenderMethod method) throws Exception {
            // Given
            String host = "unknown_host";
            message.getRequestHeader().setURI(new URI("https://" + host + ":" + serverPort, true));
            // When / Then
            ZapUnknownHostException exception =
                    assertThrows(
                            ZapUnknownHostException.class,
                            () -> method.sendWith(httpSender, message));
            assertThat(exception.getMessage(), startsWith(host));
            assertThat(exception.isFromOutgoingProxy(), is(equalTo(false)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldThrowZapSocketTimeoutExceptionIfTimeout(SenderMethod method) throws Exception {
            // Given
            int timeoutInSecs = 1;
            options.setTimeoutInSecs(timeoutInSecs);
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        Thread.sleep(TimeUnit.SECONDS.toMillis(timeoutInSecs * 2));
                    });
            // When / Then
            ZapSocketTimeoutException exception =
                    assertThrows(
                            ZapSocketTimeoutException.class,
                            () -> method.sendWith(httpSender, message));
            assertThat(exception.getTimeout(), is(equalTo(timeoutInSecs)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#httpVersionsAndSendAndReceiveMethods")
        void shouldBeSentWithDifferentHttpVersions(String version, SenderMethod method)
                throws Exception {
            // Given
            HttpRequestHeader requestHeader = message.getRequestHeader();
            requestHeader.setVersion(version);
            requestHeader.setHeader("Host", "localhost:" + serverPort);
            requestHeader.setContentLength(0);
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
            assertRequest(server.getReceivedMessages().get(0), requestMethod, requestBody);
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
                                            + "host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "content-length: 0\r\n"
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
                                            + "host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "content-length: 0\r\n"
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
                                            + "host: localhost:"
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
                                            + "host: localhost:"
                                            + serverPort
                                            + "\r\n"
                                            + "content-length: 42\r\n"
                                            + "\r\n")));
            assertThat(receivedMessage.getRequestBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldBeUpdatedWithExactContentLengthHeaderCase(
                String requestMethod, SenderMethod method) throws Exception {
            // Given
            message.getRequestHeader().setHeader("Host", "localhost:" + serverPort);
            message.getRequestHeader().addHeader("content-length", "0");
            message.getRequestHeader().addHeader("OtherHeader", "SomeValue");
            // When
            method.sendWith(httpSender, message);
            // Then
            String expectedRequestHeader =
                    "GET "
                            + getServerUri("/")
                            + " HTTP/1.1\r\n"
                            + "host: localhost:"
                            + serverPort
                            + "\r\n"
                            + "content-length: 0\r\n"
                            + "OtherHeader: SomeValue\r\n"
                            + "\r\n";
            assertThat(message.getRequestHeader().toString(), is(equalTo(expectedRequestHeader)));
            assertThat(server.getReceivedMessages(), hasSize(1));
            HttpMessage receivedMessage = server.getReceivedMessages().get(0);
            assertThat(
                    receivedMessage.getRequestHeader().toString(),
                    is(equalTo(expectedRequestHeader)));
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
                assertRequest(receivedMessage, requestMethod, requestBody);
            }
        }

        @Test
        void shouldBeSentWithExistingNtlmAuthentication() throws Exception {
            // Given
            AtomicInteger requestCount = new AtomicInteger();
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        var response = "HTTP/1.1 200 OK";

                        int current = requestCount.getAndIncrement();
                        if (current == 0) {
                            response =
                                    "HTTP/1.1 401 Unauthorized\n"
                                            + "WWW-Authenticate: Negotiate\n"
                                            + "WWW-Authenticate: NTLM\n";
                        } else if (current == 1) {
                            response =
                                    "HTTP/1.1 401 Unauthorized\n"
                                            + "WWW-Authenticate: NTLM TlRMTVNTUAACAAAAHAAcADgAAAAFgooCSahi6Sp2OccAAAAAAAAAAJAAkABUAAAACgBdWAAAAA9XAEkATgBEAEUAVgAyADMAMQAxAEUAVgBBAEwAAgAcAFcASQBOAEQARQBWADIAMwAxADEARQBWAEEATAABABwAVwBJAE4ARABFAFYAMgAzADEAMQBFAFYAQQBMAAQAHABXAGkAbgBEAGUAdgAyADMAMQAxAEUAdgBhAGwAAwAcAFcAaQBuAEQAZQB2ADIAMwAxADEARQB2AGEAbAAHAAgAs59Pa0JY2gEAAAAA\n";
                        }
                        msg.getResponseHeader().setMessage(response);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });

            HttpMessage initialRequest = createMessage(HttpRequestHeader.GET, "/");
            String challenge = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=";
            HttpMessage challengeRequest = createMessage(HttpRequestHeader.GET, "/");
            challengeRequest.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, challenge);
            String credentials =
                    "NTLM TlRMTVNTUAADAAAAGAAYAF4AAAC8ALwAdgAAAAAAAABAAAAACAAIAEAAAAAWABYASAAAAAAAAAAAAAAABYIIAFUAcwBlAHIAVwBPAFIASwBTAFQAQQBUAEkATwBOAHizK+ek+7dlUzjnzJbXZRPGU9/At2s/Pl3sNL5zHWFfZkQYYCyprcMBAQAAAAAAAIBdvo1CWNoB4SlHsS/Dj0EAAAAAAgAcAFcASQBOAEQARQBWADIAMwAxADEARQBWAEEATAABABwAVwBJAE4ARABFAFYAMgAzADEAMQBFAFYAQQBMAAQAHABXAGkAbgBEAGUAdgAyADMAMQAxAEUAdgBhAGwAAwAcAFcAaQBuAEQAZQB2ADIAMwAxADEARQB2AGEAbAAHAAgAs59Pa0JY2gEAAAAA";
            HttpMessage credentialsRequest = createMessage(HttpRequestHeader.GET, "/");
            credentialsRequest.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, credentials);
            // When
            httpSender.sendAndReceive(initialRequest);
            httpSender.sendAndReceive(challengeRequest);
            httpSender.sendAndReceive(credentialsRequest);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(3));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo(challenge)));
            assertThat(
                    server.getReceivedMessages()
                            .get(2)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo(credentials)));
            assertThat(message.getResponseBody().toString(), is(not(equalTo(SERVER_RESPONSE))));
        }

        @Test
        void shouldBeSentWithExistingIncorrectNtlmAuthentication() throws Exception {
            // Given
            AtomicInteger requestCount = new AtomicInteger();
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        var response =
                                "HTTP/1.1 401 Unauthorized\n"
                                        + "WWW-Authenticate: Negotiate\n"
                                        + "WWW-Authenticate: NTLM\n";
                        if (requestCount.getAndIncrement() == 1) {
                            response =
                                    "HTTP/1.1 401 Unauthorized\n"
                                            + "WWW-Authenticate: NTLM TlRMTVNTUAACAAAAHAAcADgAAAAFgooCpgp96tbFDRsAAAAAAAAAAJAAkABUAAAACgBdWAAAAA9XAEkATgBEAEUAVgAyADMAMQAxAEUAVgBBAEwAAgAcAFcASQBOAEQARQBWADIAMwAxADEARQBWAEEATAABABwAVwBJAE4ARABFAFYAMgAzADEAMQBFAFYAQQBMAAQAHABXAGkAbgBEAGUAdgAyADMAMQAxAEUAdgBhAGwAAwAcAFcAaQBuAEQAZQB2ADIAMwAxADEARQB2AGEAbAAHAAgA2oCaJUNY2gEAAAAA";
                        }
                        msg.getResponseHeader().setMessage(response);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });

            HttpMessage initialRequest = createMessage(HttpRequestHeader.GET, "/");
            String challenge = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=";
            HttpMessage challengeRequest = createMessage(HttpRequestHeader.GET, "/");
            challengeRequest.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, challenge);
            String credentials =
                    "NTLM TlRMTVNTUAADAAAAGAAYAFgAAAC8ALwAcAAAAAAAAABAAAAAAgACAEAAAAAWABYAQgAAAAAAAAAAAAAABYIIAFgAVwBPAFIASwBTAFQAQQBUAEkATwBOAP6yoXsqfSJ6sdpm5BsUKdLlurkW6n/9a5cWdamhy5bZRNgkApsZKiIBAQAAAAAAAIC+SixDWNoBSh9I+fDqnVEAAAAAAgAcAFcASQBOAEQARQBWADIAMwAxADEARQBWAEEATAABABwAVwBJAE4ARABFAFYAMgAzADEAMQBFAFYAQQBMAAQAHABXAGkAbgBEAGUAdgAyADMAMQAxAEUAdgBhAGwAAwAcAFcAaQBuAEQAZQB2ADIAMwAxADEARQB2AGEAbAAHAAgA2oCaJUNY2gEAAAAA";
            HttpMessage credentialsRequest = createMessage(HttpRequestHeader.GET, "/");
            credentialsRequest.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, credentials);
            // When
            httpSender.sendAndReceive(initialRequest);
            httpSender.sendAndReceive(challengeRequest);
            httpSender.sendAndReceive(credentialsRequest);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(3));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo(challenge)));
            assertThat(
                    server.getReceivedMessages()
                            .get(2)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo(credentials)));
            assertThat(message.getResponseBody().toString(), is(not(equalTo(SERVER_RESPONSE))));
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
                    "HTTP/1.1 500 Reason\r\nheader1: HeaderValue\r\nx: y\r\ncontent-length: 13\r\n\r\n";
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
        void shouldHaveNoBodyWhenNoBodyExpected(SenderMethod method) throws Exception {
            // Given
            String responseHeader = "HTTP/1.1 204\r\n\r\n";
            server.setHttpMessageHandler((ctx, msg) -> msg.setResponseHeader(responseHeader));
            message.setResponseBody("Should be cleared.");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(1));
            assertThat(message.getResponseHeader().toString(), is(equalTo(responseHeader)));
            assertThat(message.getResponseBody().toString(), is(equalTo("")));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeReceivedEvenWithLessContentThanContentLength(SenderMethod method)
                throws Exception {
            // Given
            String responseHeader =
                    "HTTP/1.1 200 OK\r\ncontent-length: 420\r\nConnection: close\r\n\r\n";
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
            String responseHeader = "HTTP/1.1 200 OK\r\nJ/ψ:  → VP\r\ncontent-length: 0\r\n\r\n";
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
                                out, "HTTP/1.1 200 OK\r\ncontent-length: " + size + "\r\n\r\n");
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

        @Test
        void shouldBeDownloadedToFileEvenIfNoBodyExpected(@TempDir Path dir) throws Exception {
            // Given
            Path file = Files.createTempDirectory(dir, "downloads").resolve("download");
            server.setRawHandler(
                    (ctx, msg) -> {
                        ByteBuf out = ctx.alloc().buffer();
                        ByteBufUtil.writeAscii(out, "HTTP/1.1 204\r\n\r\n");
                        ctx.writeAndFlush(out).addListener(ChannelFutureListener.CLOSE);
                    });
            // When
            httpSender.sendAndReceive(message, file);
            // Then
            assertThat(Files.size(file), is(equalTo(0L)));
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

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#noBodyKeepAliveResponseAndSendAndReceiveMethods")
        void shouldContainUserObjectWithConnectionClosed(String responseHeader, SenderMethod method)
                throws Exception {
            // Given
            server.setRawHandler(
                    (ctx, msg) -> {
                        ByteBuf out = ctx.alloc().buffer();
                        ByteBufUtil.writeAscii(out, responseHeader);
                        ctx.write(out);
                        ctx.writeAndFlush(Unpooled.EMPTY_BUFFER)
                                .addListener(ChannelFutureListener.CLOSE);
                    });
            message.getRequestHeader().setHeader(HttpHeader.CONNECTION, HttpHeader._KEEP_ALIVE);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(message.getResponseHeader().toString(), is(equalTo(responseHeader)));
            assertThat(message.getResponseBody().toString(), is(equalTo("")));
            assertThat(message.getUserObject(), is(instanceOf(Map.class)));
            assertThat(
                    (Map<?, ?>) message.getUserObject(),
                    hasEntry("connection.closed", Boolean.TRUE));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#emptyKeepAliveResponseAndSendAndReceiveMethods")
        void shouldNotContainUserObjectWithConnectionClosedIfNotClosed(
                String responseHeader, SenderMethod method) throws Exception {
            // Given
            server.setRawHandler(
                    (ctx, msg) -> {
                        ByteBuf out = ctx.alloc().buffer();
                        ByteBufUtil.writeAscii(out, responseHeader);
                        ctx.write(out);
                        ctx.writeAndFlush(Unpooled.EMPTY_BUFFER);
                    });
            message.getRequestHeader().setHeader(HttpHeader.CONNECTION, HttpHeader._KEEP_ALIVE);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(message.getResponseHeader().toString(), is(equalTo(responseHeader)));
            assertThat(message.getResponseBody().toString(), is(equalTo("")));
            assertThat(message.getUserObject(), is(nullValue()));
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

            private Supplier<String> headerSupplier;
            private Supplier<String> chunkedBodySupplier;

            @BeforeEach
            void setUp() {
                headerSupplier = () -> RESPONSE_HEADER;
                server.setHttpMessageHandler(
                        (ctx, msg) -> {
                            msg.setResponseHeader(headerSupplier.get());
                            msg.setResponseBody(chunkedBodySupplier.get());
                        });
            }

            private void assertResponseNotChunked() {
                assertResponseNotChunked(249, RESPONSE_BODY);
            }

            private void assertResponseNotChunked(int contentLength, String body) {
                assertThat(server.getReceivedMessages(), hasSize(1));
                assertThat(
                        message.getResponseHeader().getHeader("Transfer-Encoding"),
                        is(nullValue()));
                assertThat(message.getResponseBody().toString(), is(equalTo(body)));
                assertThat(
                        message.getResponseHeader().getContentLength(), is(equalTo(contentLength)));
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

            @ParameterizedTest
            @MethodSource(
                    "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
            void shouldHaveChunksRemovedButNoContentLengthIfSse(SenderMethod method)
                    throws Exception {
                // Given
                headerSupplier =
                        () ->
                                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n";
                chunkedBodySupplier =
                        () ->
                                Integer.toHexString(RESPONSE_BODY.length())
                                        + "\r\n"
                                        + RESPONSE_BODY
                                        + "\r\n0\r\n\r\n";
                // When
                method.sendWith(httpSender, message);
                // Then
                assertResponseNotChunked(-1, "");
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
                                    () -> globalCookieStore,
                                    options,
                                    clientCertificatesOptions,
                                    () -> null),
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
    class HostNormalisation {

        private HttpMessage messageReceived;
        private String serverHost;

        @BeforeEach
        void setup() throws Exception {
            serverHost = "localhost:" + serverPort;
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        messageReceived = msg;
                        msg.setResponseHeader("HTTP/1.1 200\r\nContent-Length: 0");
                    });

            message.setRequestHeader("GET " + getServerUri("/") + " HTTP/1.1");
            message.getRequestHeader().setHeader("a", "1");
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, serverHost);
            message.getRequestHeader().setHeader("b", "2");
        }

        @AfterEach
        void teardown() throws IOException {
            server.close();
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeEnabledByDefaultAndRemoveDuplicatedHostHeaders(SenderMethod method)
                throws Exception {
            // Given
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.com");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.org");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nhost: " + serverHost + "\r\nb: 2\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeEnabledByDefaultAndAddHostHeader(SenderMethod method) throws Exception {
            // Given
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, null);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nb: 2\r\nhost: " + serverHost + "\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeEnabledWithTrue(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(Map.of("host.normalization", Boolean.TRUE));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.org");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.com");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nhost: " + serverHost + "\r\nb: 2\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeEnabledWithInvalidValue(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(Map.of("host.normalization", "not valid boolean"));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.com");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.org");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nhost: " + serverHost + "\r\nb: 2\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeDisabledWithFalse(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(Map.of("host.normalization", Boolean.FALSE));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.com");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.org");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString(
                            "a: 1\r\nhost: example.com\r\nb: 2\r\nhost: example.org\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldAddNoHostHeaderWhenDisabled(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(Map.of("host.normalization", Boolean.FALSE));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, null);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nb: 2\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldAllowHostOverrideEvenWhenEnabled(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(
                    Map.of("host.normalization", Boolean.TRUE, "host", "override.example.org"));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.com");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.org");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString("a: 1\r\nhost: override.example.org\r\nb: 2\r\n\r\n"));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldIgnoreHostOverrideWhenDisabled(SenderMethod method) throws Exception {
            // Given
            message.setUserObject(
                    Map.of("host.normalization", Boolean.FALSE, "host", "override.example.org"));
            message.getRequestHeader().setHeader(HttpRequestHeader.HOST, "example.com");
            message.getRequestHeader().addHeader(HttpRequestHeader.HOST, "example.org");
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    messageReceived.getRequestHeader().toString(),
                    containsString(
                            "a: 1\r\nhost: example.com\r\nb: 2\r\nhost: example.org\r\n\r\n"));
        }
    }

    @Nested
    class PersistentConnection {

        @BeforeEach
        void setup() {
            server.setHttpMessageHandler((ctx, msg) -> msg.setResponseHeader("HTTP/1.1 101"));

            message.getRequestHeader().setHeader("Host", "localhost:" + serverPort);
            message.setUserObject(
                    Collections.singletonMap("connection.manual.persistent", Boolean.TRUE));
        }

        @AfterEach
        void teardown() throws IOException {
            server.close();
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeKeptOpenIfListenerWantsIt(SenderMethod method) throws Exception {
            // Given
            given(
                            legacyProxyListenerHandler.notifyPersistentConnectionListener(
                                    any(), any(), any()))
                    .willReturn(true);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertSocketClosed(false);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeClosedIfNoListenerWantsIt(SenderMethod method) throws Exception {
            // Given
            given(
                            legacyProxyListenerHandler.notifyPersistentConnectionListener(
                                    any(), any(), any()))
                    .willReturn(false);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertSocketClosed(true);
        }

        @SuppressWarnings("deprecation")
        private void assertSocketClosed(boolean closed) throws IOException {
            ArgumentCaptor<org.zaproxy.zap.ZapGetMethod> methodCaptor =
                    ArgumentCaptor.forClass(org.zaproxy.zap.ZapGetMethod.class);
            verify(legacyProxyListenerHandler)
                    .notifyPersistentConnectionListener(
                            eq(message), isNull(), methodCaptor.capture());
            org.zaproxy.zap.ZapGetMethod getMethod = methodCaptor.getValue();
            try (Socket socket = getMethod.getUpgradedConnection()) {
                assertThat(socket.isConnected(), is(equalTo(true)));
                assertThat(socket.isClosed(), is(equalTo(closed)));
            }
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
                        if (HttpRequestHeader.CONNECT.equals(msg.getRequestHeader().getMethod())) {
                            msg.setResponseHeader("HTTP/1.1 200 OK");
                            return;
                        }
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

        private void proxyWithAuth(String authRealm) {
            proxy.setHttpMessageHandler(
                    (ctx, msg) -> {
                        String authorization =
                                msg.getRequestHeader().getHeader(HttpHeader.PROXY_AUTHORIZATION);
                        if (authorization == null
                                || !"Basic dXNlcm5hbWU6cGFzc3dvcmQ=".equals(authorization)) {
                            msg.setResponseHeader(
                                    "HTTP/1.1 407\r\nProxy-Authenticate: Basic realm=\""
                                            + authRealm
                                            + "\"\r\n");
                            if (!HttpRequestHeader.HEAD.equals(
                                    msg.getRequestHeader().getMethod())) {
                                msg.setResponseBody(PROXY_RESPONSE);
                                msg.getResponseHeader()
                                        .setContentLength(msg.getResponseBody().length());
                            }
                            return;
                        }

                        msg.setResponseHeader("HTTP/1.1 200\r\n");
                        if (!HttpRequestHeader.HEAD.equals(msg.getRequestHeader().getMethod())) {
                            msg.setResponseBody(SERVER_RESPONSE);
                            msg.getResponseHeader()
                                    .setContentLength(msg.getResponseBody().length());
                        }
                    });
        }

        @Test
        void shouldThrowZapUnknownHostExceptionIfProxyHostUnknown() throws Exception {
            // Given
            String proxyHost = "proxy.unknown_host";
            configOptionsWithProxy(proxyHost, proxyPort);
            // When / Then
            ZapUnknownHostException exception =
                    assertThrows(
                            ZapUnknownHostException.class,
                            () -> httpSender.sendAndReceive(message));
            assertThat(proxy.getReceivedMessages(), hasSize(0));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertThat(exception.getMessage(), startsWith(proxyHost));
            assertThat(exception.isFromOutgoingProxy(), is(equalTo(true)));
        }

        @Test
        void shouldProxyHttpIfEnabled() throws Exception {
            // Given
            configOptionsWithProxy("localhost", proxyPort);
            message.getRequestHeader().setSecure(false);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertResponseBody(message, PROXY_RESPONSE);
        }

        @Test
        void shouldProxyHttpsIfEnabled() throws Exception {
            // Given
            configOptionsWithProxy("localhost", proxyPort);
            message.getRequestHeader().setSecure(true);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(2));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getPrimeHeader(),
                    is(equalTo("CONNECT localhost:" + serverPort + " HTTP/1.1")));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(
                    proxy.getReceivedMessages().get(1).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertResponseBody(message, PROXY_RESPONSE);
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
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @Test
        void shouldNotAuthenticateToProxyIfAuthDisabled() throws Exception {
            // Given
            proxyWithAuth("");
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
            assertResponseBody(message, PROXY_RESPONSE);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldAuthenticateToProxy(String requestMethod, SenderMethod method) throws Exception {
            // Given
            String authRealm = "SomeRealm";
            proxyWithAuth(authRealm);
            configOptionsWithProxy("localhost", proxyPort, authRealm);
            message.getRequestHeader().setMethod(requestMethod);
            // When
            method.sendWith(httpSender, message);
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
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldReauthenticateIfRemoveUserDefinedAuthHeadersSet(
                String requestMethod, SenderMethod method) throws Exception {
            // Given
            String authRealm = "SomeRealm";
            proxyWithAuth(authRealm);
            configOptionsWithProxy("localhost", proxyPort, authRealm);
            httpSender.setRemoveUserDefinedAuthHeaders(true);
            message.getRequestHeader()
                    .setHeader(HttpHeader.PROXY_AUTHORIZATION, "Basic NotValidCredentials");
            message.getRequestHeader().setMethod(requestMethod);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(3));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.PROXY_AUTHORIZATION),
                    is(equalTo("Basic NotValidCredentials")));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.PROXY_AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    proxy.getReceivedMessages().get(1).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(2)
                            .getRequestHeader()
                            .getHeader(HttpHeader.PROXY_AUTHORIZATION),
                    is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
            assertThat(
                    proxy.getReceivedMessages().get(2).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldNotReauthenticateIfRemoveUserDefinedAuthHeadersNotSet(
                String requestMethod, SenderMethod method) throws Exception {
            // Given
            String authRealm = "SomeRealm";
            proxyWithAuth(authRealm);
            configOptionsWithProxy("localhost", proxyPort, authRealm);
            httpSender.setRemoveUserDefinedAuthHeaders(false);
            message.getRequestHeader()
                    .setHeader(HttpHeader.PROXY_AUTHORIZATION, "Basic NotValidCredentials");
            message.getRequestHeader().setMethod(requestMethod);
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertThat(
                    proxy.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.PROXY_AUTHORIZATION),
                    is(equalTo("Basic NotValidCredentials")));
            assertThat(
                    proxy.getReceivedMessages().get(0).getRequestHeader().getHeader("host"),
                    is(equalTo("localhost:" + serverPort)));
            assertThat(server.getReceivedMessages(), hasSize(0));
            assertResponseBody(message, PROXY_RESPONSE);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldNotBasicAuthenticateToProxyIfRealmMismatch(
                String requestMethod, SenderMethod method) throws Exception {
            // Given
            proxyWithAuth("SomeRealm");
            configOptionsWithProxy("localhost", proxyPort, "NotSomeRealm");
            message.getRequestHeader().setMethod(requestMethod);
            // When
            method.sendWith(httpSender, message);
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
            assertResponseBody(message, PROXY_RESPONSE);
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#requestMethodsAndSendAndReceiveMethods")
        void shouldSendRequestWithBodyForAnyMethod(String requestMethod, SenderMethod method)
                throws Exception {
            // Given
            configOptionsWithProxy("localhost", proxyPort);
            String requestBody = "Request Body";
            message.getRequestHeader().setMethod(requestMethod);
            message.setRequestBody(requestBody);
            message.getRequestHeader().setContentLength(message.getRequestBody().length());
            // When
            method.sendWith(httpSender, message);
            // Then
            assertThat(proxy.getReceivedMessages(), hasSize(1));
            assertRequest(proxy.getReceivedMessages().get(0), requestMethod, requestBody);
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

    @Nested
    class Auth {

        private String authRealm = "SomeRealm";
        private User user;

        @BeforeEach
        void setup() throws IOException {
            user = mock(User.class);
            given(user.isAuthenticated(any()))
                    .willAnswer(
                            new Answer<Boolean>() {

                                @Override
                                public Boolean answer(InvocationOnMock invocation)
                                        throws Throwable {
                                    HttpMessage msg = invocation.getArgument(0);
                                    return SERVER_RESPONSE.equals(msg.getResponseBody().toString());
                                }
                            });
            HttpState httpState = new HttpState();
            httpState.setCredentials(
                    new AuthScope("localhost", serverPort, authRealm),
                    new NTCredentials(
                            "username",
                            "password",
                            InetAddress.getLocalHost().getCanonicalHostName(),
                            authRealm));
            given(user.getCorrespondingHttpState()).willReturn(httpState);

            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        String authorization =
                                msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
                        if (authorization == null
                                || !"Basic dXNlcm5hbWU6cGFzc3dvcmQ=".equals(authorization)) {
                            msg.setResponseHeader(
                                    "HTTP/1.1 401\r\nWWW-Authenticate: Basic realm=\""
                                            + authRealm
                                            + "\"\r\n");
                            msg.getResponseHeader().setContentLength(0);
                            return;
                        }

                        msg.setResponseHeader("HTTP/1.1 200\r\n");
                        msg.setResponseBody(SERVER_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
        }

        @Test
        void shouldAuthenticateToServer() throws Exception {
            // Given
            message.setRequestingUser(user);
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @Test
        void shouldBasicAuthWithoutRealm() throws Exception {
            // Given
            message.setRequestingUser(user);
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        String authorization =
                                msg.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION);
                        if (authorization == null
                                || !"Basic dXNlcm5hbWU6cGFzc3dvcmQ=".equals(authorization)) {
                            msg.setResponseHeader("HTTP/1.1 401\r\nWWW-Authenticate: Basic\r\n");
                            msg.getResponseHeader().setContentLength(0);
                            return;
                        }

                        msg.setResponseHeader("HTTP/1.1 200\r\n");
                        msg.setResponseBody(SERVER_RESPONSE);
                        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
                    });
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @Test
        void shouldReauthenticateIfRemoveUserDefinedAuthHeadersSet() throws Exception {
            // Given
            message.setRequestingUser(user);
            httpSender.setRemoveUserDefinedAuthHeaders(true);
            message.getRequestHeader()
                    .setHeader(HttpHeader.AUTHORIZATION, "Basic NotValidCredentials");
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(3));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic NotValidCredentials")));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(nullValue()));
            assertThat(
                    server.getReceivedMessages()
                            .get(2)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
            assertResponseBody(message, SERVER_RESPONSE);
        }

        @Test
        void shouldNotReauthenticateIfRemoveUserDefinedAuthHeadersNotSet() throws Exception {
            // Given
            message.setRequestingUser(user);
            message.getRequestHeader()
                    .setHeader(HttpHeader.AUTHORIZATION, "Basic NotValidCredentials");
            // When
            httpSender.sendAndReceive(message);
            // Then
            assertThat(server.getReceivedMessages(), hasSize(2));
            assertThat(
                    server.getReceivedMessages()
                            .get(0)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic NotValidCredentials")));
            assertThat(
                    server.getReceivedMessages()
                            .get(1)
                            .getRequestHeader()
                            .getHeader(HttpHeader.AUTHORIZATION),
                    is(equalTo("Basic NotValidCredentials")));
            assertThat(message.getResponseBody().toString(), is(not(equalTo(SERVER_RESPONSE))));
        }
    }

    @Nested
    class Cookies {

        private static final String EXPECTED_COOKIE_HEADER =
                "a=\"a-value\"; b=b-value\"; c=\"c-value; d=d -value; e=e-v; f=f-value; F=F-value; g=\"g; \"nameA=value; nameB\"=value; \"nameC\"=value; name a=value; name     c=value     c; X; W=";

        @BeforeEach
        void setup() throws Exception {
            server.setHttpMessageHandler(
                    (ctx, msg) -> {
                        msg.setResponseHeader(
                                "HTTP/1.1 200\r\ncontent-length: 0\r\n"
                                        + "Set-Cookie: a=\"a-value\";\r\n"
                                        + "Set-Cookie: b=b-value\"\r\n"
                                        + "Set-Cookie: c=\"c-value       \r\n"
                                        + "Set-Cookie: d=d -value\r\n"
                                        + "Set-Cookie: e=e-v;alue\r\n"
                                        + "Set-Cookie: f=f-value\r\n"
                                        + "Set-Cookie: F=F-value        \r\n"
                                        + "Set-Cookie: g=\"g;-valu\"e\r\n"
                                        + "Set-Cookie: \"nameA=value\r\n"
                                        + "Set-Cookie: nameB\"=value\r\n"
                                        + "Set-Cookie: \"nameC\"=value\r\n"
                                        + "Set-Cookie:       name a     =value\r\n"
                                        + "Set-Cookie: name     c =  value     c \r\n"
                                        + "Set-Cookie: =X\r\n"
                                        + "Set-Cookie: W=\r\n");
                    });

            message.setRequestHeader("GET " + getServerUri("/") + " HTTP/1.1");
            httpSender.setUseGlobalState(false);
        }

        @AfterEach
        void teardown() throws IOException {
            server.close();
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldNotBeHandleWhenNoEnabled(SenderMethod method) throws Exception {
            // Given
            httpSender.setUseCookies(false);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(message.getRequestHeader().getHeader("cookie"), is(nullValue()));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeHandledWhenEnabled(SenderMethod method) throws Exception {
            // Given
            httpSender.setUseCookies(true);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(message.getRequestHeader().getHeader("cookie"), is(not(nullValue())));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentLikeABrowserSends(SenderMethod method) throws Exception {
            // Given
            httpSender.setUseCookies(true);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    message.getRequestHeader().getHeader("cookie"),
                    is(equalTo(EXPECTED_COOKIE_HEADER)));
        }

        @ParameterizedTest
        @MethodSource(
                "org.zaproxy.addon.network.internal.client.HttpSenderImplUnitTest#sendAndReceiveMethods")
        void shouldBeSentAlwaysTheSame(SenderMethod method) throws Exception {
            // Given
            httpSender.setUseCookies(true);
            // When
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            method.sendWith(httpSender, message);
            // Then
            assertThat(
                    message.getRequestHeader().getHeader("cookie"),
                    is(equalTo(EXPECTED_COOKIE_HEADER)));
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

    private void assertRequest(HttpMessage msg, String requestMethod, String requestBody) {
        assertThat(
                msg.getRequestHeader().toString(),
                is(
                        equalTo(
                                requestMethod
                                        + " "
                                        + getServerUri("/")
                                        + " HTTP/1.1\r\n"
                                        + "content-length: "
                                        + requestBody.getBytes(StandardCharsets.US_ASCII).length
                                        + "\r\n"
                                        + "host: localhost:"
                                        + serverPort
                                        + "\r\n"
                                        + "\r\n")));
        assertThat(msg.getRequestBody().toString(), is(equalTo(requestBody)));
    }

    private static void assertResponseBody(HttpMessage message, String body) {
        if (HttpRequestHeader.HEAD.equals(message.getRequestHeader().getMethod())) {
            return;
        }
        assertThat(message.getResponseBody().toString(), is(equalTo(body)));
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
