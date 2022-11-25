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
package org.zaproxy.addon.network.internal.codec;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasSize;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2Connection;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.server.BaseServer;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.addon.network.testutils.TestClient;

/** Unit test for {@link HttpToHttp2ConnectionHandler}. */
class HttpToHttp2ConnectionHandlerUnitTest {

    private static final String SERVER_ADDRESS = "127.0.0.1";

    private static NioEventLoopGroup eventLoopGroup;

    private ResponseProducer responseProducer;
    private BaseServer server;
    private HttpMessage msg;
    private TestClient client;
    private List<HttpMessage> requests;
    private List<HttpMessage> responses;
    private CountDownLatch responseReceived;

    @BeforeAll
    static void setupAll() throws Exception {
        eventLoopGroup =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-HttpToHttp2ConnectionHandlerUnitTest"));
    }

    @AfterAll
    static void tearDownAll() throws Exception {
        if (eventLoopGroup != null) {
            eventLoopGroup.shutdownGracefully();
            eventLoopGroup = null;
        }
    }

    @BeforeEach
    void setUp() {
        requests = new ArrayList<>();
        responses = new ArrayList<>();
        responseReceived = new CountDownLatch(1);
        server = new BaseServer(eventLoopGroup, this::initServerChannel);

        msg = new HttpMessage();
        client = new TestClient(SERVER_ADDRESS, this::initClientChannel);
    }

    private static HttpToHttp2ConnectionHandler createHandler(boolean server) {
        DefaultHttp2Connection connection = new DefaultHttp2Connection(server);
        return HttpToHttp2ConnectionHandler.create(
                new InboundHttp2ToHttpAdapter(connection), null, connection, HttpHeader.HTTP);
    }

    private void initServerChannel(SocketChannel ch) {
        ch.pipeline()
                .addLast(createHandler(true))
                .addLast(
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                requests.add(msg);
                                if (responseProducer != null) {
                                    responseProducer.accept(msg);
                                } else {
                                    msg.setResponseHeader("HTTP/2 200");
                                }
                                ctx.writeAndFlush(msg);
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                ctx.close();
                            }
                        });
    }

    private void initClientChannel(SocketChannel ch) {
        ch.pipeline()
                .addLast(createHandler(false))
                .addLast(
                        new SimpleChannelInboundHandler<HttpMessage>() {

                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, HttpMessage msg)
                                    throws Exception {
                                responses.add(msg);
                                responseReceived.countDown();
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
                                    throws Exception {
                                ctx.close();
                            }
                        });
    }

    @AfterEach
    void teardown() throws IOException {
        if (server != null) {
            server.stop();
            server = null;
        }

        if (client != null) {
            client.close();
            client = null;
        }
    }

    @Test
    void shouldWriteRequest() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader(
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2");
        msg.setRequestBody("Body Request");
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(requests, hasSize(1));
        HttpMessage receivedRequest = requests.get(0);
        assertRequestHeader(
                receivedRequest,
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2",
                "content-length: 12");
        assertRequestBody(receivedRequest, "Body Request");
        assertMessageProperties(receivedRequest, 3);
    }

    @Test
    void shouldWriteRequestWithBodyAndTrailers() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader(
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2");
        msg.setRequestBody("Body Request");
        Map<String, Object> properties = new HashMap<>();
        properties.put(
                "zap.h2.trailers.req",
                List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2")));
        msg.setUserObject(properties);
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(requests, hasSize(1));
        HttpMessage receivedRequest = requests.get(0);
        assertRequestHeader(
                receivedRequest,
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2",
                "content-length: 12");
        assertRequestBody(receivedRequest, "Body Request");
        assertMessageProperties(receivedRequest, 3);
        assertProperty(
                receivedRequest,
                hasEntry(
                        "zap.h2.trailers.req",
                        List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2"))));
    }

    @Test
    void shouldWriteRequestWithCustomStreamId() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader(
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2");
        msg.setRequestBody("Body Request");
        int streamId = 17;
        Map<String, Object> properties = new HashMap<>();
        properties.put("zap.h2.stream.id", streamId);
        msg.setUserObject(properties);
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(requests, hasSize(1));
        HttpMessage receivedRequest = requests.get(0);
        assertRequestHeader(
                receivedRequest,
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2",
                "content-length: 12");
        assertRequestBody(receivedRequest, "Body Request");
        assertMessageProperties(receivedRequest, streamId);
    }

    @Test
    void shouldWriteRequestWithOutBody() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader(
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2");
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(requests, hasSize(1));
        HttpMessage receivedRequest = requests.get(0);
        assertRequestHeader(
                receivedRequest,
                "METHOD http://127.0.0.1:" + port + "/path?a=b HTTP/2",
                "header-a: 1",
                "header-b: 2",
                "content-length: 0");
        assertRequestBody(receivedRequest, "");
        assertMessageProperties(receivedRequest, 3);
    }

    @Test
    void shouldWriteResponse() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader("GET http://127.0.0.1:" + port + "/ HTTP/2");
        responseProducer =
                msg -> {
                    msg.setResponseHeader("HTTP/2 200\r\nheader-a: 1\r\nheader-b: 2\r\n");
                    msg.setResponseBody("Body Response");
                };
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(responses, hasSize(1));
        HttpMessage receivedResponse = responses.get(0);
        assertResponseHeader(
                receivedResponse, "HTTP/2 200", "header-a: 1", "header-b: 2", "content-length: 13");
        assertResponseBody(receivedResponse, "Body Response");
        assertMessageProperties(receivedResponse, 3);
    }

    @Test
    void shouldWriteResponseWithBodyAndTrailers() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader("GET http://127.0.0.1:" + port + "/ HTTP/2");
        responseProducer =
                msg -> {
                    msg.setResponseHeader("HTTP/2 200\r\nheader-a: 1\r\nheader-b: 2\r\n");
                    msg.setResponseBody("Body Response");
                    @SuppressWarnings("unchecked")
                    Map<String, Object> properties = (Map<String, Object>) msg.getUserObject();
                    properties.put(
                            "zap.h2.trailers.resp",
                            List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2")));
                };
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(responses, hasSize(1));
        HttpMessage receivedResponse = responses.get(0);
        assertResponseHeader(
                receivedResponse, "HTTP/2 200", "header-a: 1", "header-b: 2", "content-length: 13");
        assertResponseBody(receivedResponse, "Body Response");
        assertMessageProperties(receivedResponse, 3);
        assertProperty(
                receivedResponse,
                hasEntry(
                        "zap.h2.trailers.resp",
                        List.of(new HttpHeaderField("a", "1"), new HttpHeaderField("b", "2"))));
    }

    @Test
    void shouldWriteResponseWithOutBody() throws Exception {
        // Given
        int port = server.start(Server.ANY_PORT);
        createRequestHeader("GET http://127.0.0.1:" + port + "/ HTTP/2");
        responseProducer =
                msg -> {
                    msg.setResponseHeader("HTTP/2 200\r\nheader-a: 1\r\nheader-b: 2\r\n");
                    msg.setResponseBody("");
                };
        // When
        client.send(port, msg);
        // Then
        waitForResponse();
        assertThat(responses, hasSize(1));
        HttpMessage receivedResponse = responses.get(0);
        assertResponseHeader(
                receivedResponse, "HTTP/2 200", "header-a: 1", "header-b: 2", "content-length: 0");
        assertResponseBody(receivedResponse, "");
        assertMessageProperties(receivedResponse, 3);
    }

    private void waitForResponse() throws InterruptedException {
        responseReceived.await(5, TimeUnit.SECONDS);
    }

    private static void assertMessageProperties(HttpMessage msg, int streamId) {
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertProperty(msg, hasEntry("zap.h2.stream.weight", (short) 16));
    }

    private static <K, V> void assertProperty(
            HttpMessage msg, Matcher<Map<? extends K, ? extends V>> matcher) {
        Object userObject = msg.getUserObject();
        assertThat(userObject, is(instanceOf(Map.class)));
        @SuppressWarnings("unchecked")
        Map<K, V> properties = (Map<K, V>) userObject;
        assertThat(properties, matcher);
    }

    private void createRequestHeader(String requestLine, String... headerFields) throws Exception {
        String allHeaderFields = mergeHeaderFields(headerFields);
        String content = requestLine + "\r\n" + allHeaderFields + "\r\n";
        msg.setRequestHeader(new HttpRequestHeader(content));
    }

    private static void assertRequestHeader(
            HttpMessage msg, String requestLine, String... headerFields) {
        assertHeader(msg.getRequestHeader(), requestLine, headerFields);
    }

    private static void assertHeader(
            HttpHeader httpHeader, String startLine, String... headerFields) {
        assertThat(httpHeader.isEmpty(), is(equalTo(false)));
        String allHeaderFields = mergeHeaderFields(headerFields);
        assertThat(
                httpHeader.toString(), is(equalTo(startLine + "\r\n" + allHeaderFields + "\r\n")));
    }

    private static String mergeHeaderFields(String[] headerFields) {
        String allHeaderFields = String.join("\r\n", headerFields);
        if (headerFields != null && headerFields.length > 0) {
            allHeaderFields += "\r\n";
        }
        return allHeaderFields;
    }

    private static void assertRequestBody(HttpMessage msg, String contents) {
        assertBody(msg.getRequestBody(), contents);
    }

    private static void assertBody(HttpBody httpBody, String contents) {
        assertThat(contents.toString(), is(equalTo(contents)));
    }

    private static void assertResponseHeader(
            HttpMessage msg, String statusLine, String... headerFields) {
        assertHeader(msg.getResponseHeader(), statusLine, headerFields);
    }

    private static void assertResponseBody(HttpMessage msg, String contents) {
        assertBody(msg.getResponseBody(), contents);
    }

    private interface ResponseProducer {

        void accept(HttpMessage msg) throws Exception;
    }
}
