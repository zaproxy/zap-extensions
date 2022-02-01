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
package org.zaproxy.addon.network.internal.server.http.handlers;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Locale;
import org.apache.commons.httpclient.HttpException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link HttpSenderHandler}. */
class HttpSenderHandlerUnitTest extends TestUtils {

    private HttpMessageHandlerContext ctx;
    private ConnectionParam connectionParam;
    private HttpSender httpSender;
    private HttpSenderHandler handler;

    @BeforeEach
    void setUp() throws IOException {
        Constant.messages = new I18N(Locale.ENGLISH);

        ctx = mock(HttpMessageHandlerContext.class);
        httpSender = mock(HttpSender.class);
        connectionParam = new ConnectionParam();
        connectionParam.load(new ZapXmlConfiguration());
        handler = new HttpSenderHandler(connectionParam, httpSender);
    }

    @Test
    void shouldThrowIfConnectionParamIsNull() {
        // Given
        ConnectionParam connectionParam = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new HttpSenderHandler(connectionParam, httpSender));
    }

    @Test
    void shouldNotHandleResponse() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(httpSender, times(0)).sendAndReceive(any());
        verify(httpSender, times(0)).sendAndReceive(any(), anyBoolean());
        verify(httpSender, times(0)).sendAndReceive(any(), any());
    }

    @Test
    void shouldSendAndReceiveMessage() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        // When
        handler.handleMessage(ctx, message);
        verifyMessageSent(message);
    }

    @Test
    void shouldSendMessageWithoutNotifyingListenersIfExcluded() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        given(ctx.isExcluded()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(httpSender, times(0)).sendAndReceive(any());
        verify(httpSender, times(0)).sendAndReceive(any(), anyBoolean());
        ArgumentCaptor<HttpRequestConfig> argument =
                ArgumentCaptor.forClass(HttpRequestConfig.class);
        verify(httpSender, times(1)).sendAndReceive(eq(message), argument.capture());
        assertThat(argument.getAllValues().get(0).isNotifyListeners(), is(equalTo(false)));
        verify(ctx).overridden();
    }

    @Test
    void shouldReturnGatewayTimeoutForTimeout() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        doThrow(SocketTimeoutException.class).when(httpSender).sendAndReceive(message);
        // When
        handler.handleMessage(ctx, message);
        verifyMessageSent(message);
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(
                message.getResponseHeader().toString(), startsWith("HTTP/1.1 504 Gateway Timeout"));
        assertThat(
                message.getResponseBody().toString(),
                is(equalTo("!network.httpsender.error.readtimeout!")));
    }

    @Test
    void shouldNotIncludeErrorBodyIfHeadRequest() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("HEAD / HTTP/1.1");
        doThrow(SocketTimeoutException.class).when(httpSender).sendAndReceive(message);
        // When
        handler.handleMessage(ctx, message);
        verifyMessageSent(message);
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(
                message.getResponseHeader().toString(), startsWith("HTTP/1.1 504 Gateway Timeout"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldReturnBadGatewayForIoException() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        doThrow(IOException.class).when(httpSender).sendAndReceive(message);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verifyMessageSent(message);
        verify(ctx, times(0)).overridden();
        verify(ctx, times(0)).close();
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 502 Bad Gateway"));
        assertThat(
                message.getResponseBody().toString(),
                allOf(startsWith("ZAP Error ["), containsString("Stack Trace:")));
    }

    @Test
    void shouldCloseWithoutSettingResponseOnHttpProtocolError() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        HttpMessage message = createServerRequest("GET / HTTP/1.1");
        doThrow(HttpException.class).when(httpSender).sendAndReceive(message);
        // When
        handler.handleMessage(ctx, message);
        verifyMessageSent(message);
        verify(ctx).close();
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.0 0\r\n\r\n"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    private void verifyMessageSent(HttpMessage message) throws IOException {
        verify(httpSender, times(1)).sendAndReceive(message);
        verify(httpSender, times(0)).sendAndReceive(any(), anyBoolean());
        verify(httpSender, times(0)).sendAndReceive(any(), any());
    }

    private static HttpMessage createServerRequest(String request) {
        try {
            return new HttpMessage(new HttpRequestHeader(request + "\r\nHost: 127.0.0.1\r\n\r\n"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
