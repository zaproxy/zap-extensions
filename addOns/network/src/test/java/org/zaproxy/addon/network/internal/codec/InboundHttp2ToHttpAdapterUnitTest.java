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
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasEntry;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http2.Http2CodecUtil;
import io.netty.handler.codec.http2.Http2Connection;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2Stream;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

/** Unit test for {@link InboundHttp2ToHttpAdapter}. */
class InboundHttp2ToHttpAdapterUnitTest {

    private static final String CONTENT_LENGTH = HttpHeader.CONTENT_LENGTH.toLowerCase(Locale.ROOT);

    private MockedStatic<Http2MessageHelper> helper;

    private int streamId;
    private int streamDependency;
    private short weight;
    private Http2Connection connection;
    private Http2Connection.PropertyKey messageKey;
    private Http2Stream stream;
    private ChannelHandlerContext ctx;
    private Map<String, Object> msgProperties;
    private HttpMessage msg;

    private InboundHttp2ToHttpAdapter adapter;

    @BeforeEach
    void setUp() {
        helper = mockStatic(Http2MessageHelper.class);

        streamId = 15;
        streamDependency = 17;
        weight = 1;
        connection = mock(Http2Connection.class);
        given(connection.newKey()).willReturn(messageKey);
        stream = mock(Http2Stream.class);
        given(stream.id()).willReturn(streamId);
        ctx = mock(ChannelHandlerContext.class);
        msgProperties = new HashMap<>();
        msg = mock(HttpMessage.class);

        adapter = new InboundHttp2ToHttpAdapter(connection);
    }

    @AfterEach
    void cleanup() {
        helper.close();
    }

    @Test
    void shouldThrowWhenCreatingWithNullConnection() {
        // Given
        connection = null;
        // When / When
        assertThrows(NullPointerException.class, () -> new InboundHttp2ToHttpAdapter(connection));
    }

    @Test
    void shouldAddItselfAsListenerToConnection() {
        // Given
        connection = mock(Http2Connection.class);
        // When
        adapter = new InboundHttp2ToHttpAdapter(connection);
        // Then
        verify(connection).addListener(adapter);
    }

    @Test
    void shouldRemoveMessageOnStreamRemoved() {
        // Given / When
        adapter.onStreamRemoved(stream);
        // Then
        verify(stream).removeProperty(messageKey);
        verifyNoMoreInteractions(stream);
    }

    @Test
    void shouldRemoveMessageOnRstStreamRead() {
        // Given
        long errorCode = Http2Error.CANCEL.code();
        given(connection.stream(streamId)).willReturn(stream);
        given(stream.getProperty(messageKey)).willReturn(mock(HttpMessage.class));
        // When
        adapter.onRstStreamRead(ctx, streamId, errorCode);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        verify(stream).removeProperty(messageKey);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldNotRemoveMessageIfNotPresentOnRstStreamRead() {
        // Given
        long errorCode = Http2Error.CANCEL.code();
        given(connection.stream(streamId)).willReturn(stream);
        // When
        adapter.onRstStreamRead(ctx, streamId, errorCode);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadHeadersIntoNewRequestAndFireChannelReadEndOfStream() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        given(connection.stream(streamId)).willReturn(stream);
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
        helper.verify(
                () ->
                        Http2MessageHelper.setHttpRequest(
                                eq(streamId), eq(headers), msgCaptor.capture()));
        HttpMessage msg = msgCaptor.getValue();
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersIntoExistingRequest() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        helper.verify(() -> Http2MessageHelper.addTrailerHeaders(streamId, headers, msg, server));
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadHeadersAndFireChannelReadIfExpectContinue() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        given(msg.getRequestHeader().getHeader("Expect")).willReturn("100-continue");
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersIntoNewResponseAndFireChannelReadEndOfStream() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        given(connection.stream(streamId)).willReturn(stream);
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
        helper.verify(
                () ->
                        Http2MessageHelper.setHttpResponse(
                                eq(streamId), eq(headers), msgCaptor.capture()));
        HttpMessage msg = msgCaptor.getValue();
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersAndFireChannelReadIfInformationalStatus() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        given(msg.getResponseHeader().getStatusCode()).willReturn(100);
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersIntoExistingResponse() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        // When
        adapter.onHeadersRead(ctx, streamId, headers, padding, endOfStream);
        // Then
        helper.verify(() -> Http2MessageHelper.addTrailerHeaders(streamId, headers, msg, server));
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadHeadersWithPriorityIntoNewRequestAndFireChannelReadEndOfStream()
            throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        given(connection.stream(streamId)).willReturn(stream);
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
        helper.verify(
                () ->
                        Http2MessageHelper.setHttpRequest(
                                eq(streamId), eq(headers), msgCaptor.capture()));
        HttpMessage msg = msgCaptor.getValue();
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertProperty(msg, hasEntry("zap.h2.stream.dependency.id", streamDependency));
        assertProperty(msg, hasEntry("zap.h2.stream.weight", weight));
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersWithPriorityIntoExistingRequest() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        helper.verify(() -> Http2MessageHelper.addTrailerHeaders(streamId, headers, msg, server));
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadHeadersWithPriorityAndFireChannelReadIfExpectContinue() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        given(msg.getRequestHeader().getHeader("Expect")).willReturn("100-continue");
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersWithPriorityIntoNewResponseAndFireChannelReadEndOfStream()
            throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        given(connection.stream(streamId)).willReturn(stream);
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
        helper.verify(
                () ->
                        Http2MessageHelper.setHttpResponse(
                                eq(streamId), eq(headers), msgCaptor.capture()));
        HttpMessage msg = msgCaptor.getValue();
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersWithPriorityAndFireChannelReadIfInformationalStatus() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        given(msg.getResponseHeader().getStatusCode()).willReturn(100);
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        assertFireChannelRead(msg, server, 0);
    }

    @Test
    void shouldReadHeadersWithPriorityIntoExistingResponse() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        msgInStream(server);
        // When
        adapter.onHeadersRead(
                ctx, streamId, headers, streamDependency, weight, false, padding, endOfStream);
        // Then
        helper.verify(() -> Http2MessageHelper.addTrailerHeaders(streamId, headers, msg, server));
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadDataIntoRequestBody() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int readableBytes = 123;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        // When
        int result = adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        verifyDataConsumed(data, msg.getRequestBody(), result, readableBytes, padding);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadDataIntoRequestBodyAndFireChannelReadIfEndOfStream() throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        int readableBytes = 123;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        given(msg.getRequestBody().length()).willReturn(readableBytes);
        // When
        int result = adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        verifyDataConsumed(data, msg.getRequestBody(), result, readableBytes, padding);
        assertFireChannelRead(server, readableBytes);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                HttpRequestHeader.GET,
                HttpRequestHeader.CONNECT,
                HttpRequestHeader.DELETE,
                HttpRequestHeader.HEAD,
                HttpRequestHeader.TRACE
            })
    void shouldRemoveContentLengthOnFireChannelReadForMethodsWithoutExpectedBody(String method)
            throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        int readableBytes = 0;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        given(msg.getRequestBody().length()).willReturn(readableBytes);
        given(msg.getRequestHeader().getMethod()).willReturn(method);
        // When
        adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        assertFireChannelRead(server, null);
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpRequestHeader.POST, HttpRequestHeader.PUT})
    void shouldNotRemoveContentLengthOnFireChannelReadForMethodsWithExpectedBody(String method)
            throws Exception {
        // Given
        boolean server = true;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        int readableBytes = 0;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        given(msg.getRequestBody().length()).willReturn(readableBytes);
        given(msg.getRequestHeader().getMethod()).willReturn(method);
        // When
        adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        assertFireChannelRead(server, readableBytes);
    }

    @Test
    void shouldReadDataIntoResponseBody() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = false;
        int readableBytes = 123;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        // When
        int result = adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        verifyDataConsumed(data, msg.getResponseBody(), result, readableBytes, padding);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
    }

    @Test
    void shouldReadDataIntoResponseBodyAndFireChannelReadIfEndOfStream() throws Exception {
        // Given
        boolean server = false;
        given(connection.isServer()).willReturn(server);
        boolean endOfStream = true;
        int readableBytes = 123;
        ByteBuf data = mockData(readableBytes);
        int padding = 321;
        msgInStream(server);
        given(msg.getResponseBody().length()).willReturn(readableBytes);
        // When
        int result = adapter.onDataRead(ctx, streamId, data, padding, endOfStream);
        // Then
        verifyDataConsumed(data, msg.getResponseBody(), result, readableBytes, padding);
        assertFireChannelRead(server, readableBytes);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldThrowIfNoMessageOnDataRead(boolean server) {
        // Given
        given(connection.isServer()).willReturn(server);
        given(connection.stream(streamId)).willReturn(stream);
        given(stream.getProperty(messageKey)).willReturn(null);
        int padding = 321;
        // When
        Http2Exception exception =
                assertThrows(
                        Http2Exception.class,
                        () ->
                                adapter.onDataRead(
                                        ctx, streamId, mock(ByteBuf.class), padding, false));
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
        assertThat(exception.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(
                exception.getMessage(),
                is(equalTo("Data Frame received for unknown stream id " + streamId)));
    }

    @Test
    void shouldReadPushPromise() throws Exception {
        // Given
        given(connection.isServer()).willReturn(false);
        given(connection.stream(streamId)).willReturn(stream);
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        adapter.onPushPromiseRead(ctx, 17, streamId, headers, padding);
        // Then
        verify(connection).stream(streamId);
        verify(stream, times(2)).getProperty(messageKey);
        ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
        helper.verify(
                () ->
                        Http2MessageHelper.setHttpRequest(
                                eq(streamId), eq(headers), msgCaptor.capture()));
        HttpMessage msg = msgCaptor.getValue();
        assertProperty(msg, hasEntry("zap.h2", Boolean.TRUE));
        assertProperty(msg, hasEntry("zap.h2.stream.id", streamId));
        assertProperty(
                msg, hasEntry("zap.h2.stream.weight", Http2CodecUtil.DEFAULT_PRIORITY_WEIGHT));
        assertProperty(msg, hasEntry("zap.h2.stream.promise", Boolean.TRUE));
    }

    @Test
    void shouldThrowIfExistingMessageOnReadPushPromise() {
        // Given
        given(connection.isServer()).willReturn(false);
        given(connection.stream(streamId)).willReturn(stream);
        given(stream.getProperty(messageKey)).willReturn(mock(HttpMessage.class));
        int padding = 321;
        Http2Headers headers = mock(Http2Headers.class);
        // When
        Http2Exception exception =
                assertThrows(
                        Http2Exception.class,
                        () -> adapter.onPushPromiseRead(ctx, 17, streamId, headers, padding));
        // Then
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        verifyNoMoreInteractions(stream);
        verifyNoInteractions(ctx);
        assertThat(exception.error(), is(equalTo(Http2Error.PROTOCOL_ERROR)));
        assertThat(
                exception.getMessage(),
                is(equalTo("Push Promise Frame received for pre-existing stream id " + streamId)));
    }

    private void msgInStream(boolean request) {
        given(connection.stream(streamId)).willReturn(stream);
        given(stream.getProperty(messageKey)).willReturn(msg);
        given(msg.getUserObject()).willReturn(msgProperties);

        if (request) {
            given(msg.getRequestHeader()).willReturn(mock(HttpRequestHeader.class));
            given(msg.getRequestBody()).willReturn(mock(HttpRequestBody.class));
        } else {
            given(msg.getResponseHeader()).willReturn(mock(HttpResponseHeader.class));
            given(msg.getResponseBody()).willReturn(mock(HttpResponseBody.class));
        }
    }

    private static ByteBuf mockData(int readableBytes) {
        ByteBuf data = mock(ByteBuf.class);
        given(data.readableBytes()).willReturn(readableBytes);
        return data;
    }

    private void verifyDataConsumed(
            ByteBuf data, HttpBody body, int result, int readableBytes, int padding) {
        verify(connection).stream(streamId);
        verify(stream).getProperty(messageKey);
        ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
        verify(data).readBytes(dataCaptor.capture(), eq(0), eq(readableBytes));
        byte[] dataRead = dataCaptor.getValue();
        verify(body).append(dataRead, readableBytes);
        assertThat(dataRead.length, is(equalTo(readableBytes)));
        assertThat(result, is(equalTo(readableBytes + padding)));
    }

    private void assertFireChannelRead(boolean request, Integer contentLength) {
        verify(stream).removeProperty(messageKey);
        HttpHeader header = request ? msg.getRequestHeader() : msg.getResponseHeader();
        if (contentLength != null) {
            verify(header).setContentLength(contentLength);
        } else {
            assertThat(request, is(equalTo(true)));
            verify(header, times(0)).setContentLength(anyInt());
            verify(header).setHeader(CONTENT_LENGTH, null);
        }
        verify(ctx).fireChannelRead(msg);
        verifyNoMoreInteractions(ctx);
    }

    private void assertFireChannelRead(HttpMessage msg, boolean request, Integer contentLength) {
        verify(stream).removeProperty(messageKey);
        HttpHeader header = request ? msg.getRequestHeader() : msg.getResponseHeader();
        if (contentLength != null) {
            assertThat(header.getContentLength(), is(equalTo(contentLength)));
        } else {
            assertThat(request, is(equalTo(true)));
            assertThat(header.getContentLength(), is(equalTo(-1)));
            assertThat(header.getHeader(CONTENT_LENGTH), is(nullValue()));
        }
        verify(ctx).fireChannelRead(msg);
        verifyNoMoreInteractions(ctx);
    }

    private static <K, V> void assertProperty(
            HttpMessage msg, Matcher<Map<? extends K, ? extends V>> matcher) {
        Object userObject = msg.getUserObject();
        assertThat(userObject, is(instanceOf(Map.class)));
        @SuppressWarnings("unchecked")
        Map<K, V> properties = (Map<K, V>) userObject;
        assertThat(properties, matcher);
    }
}
