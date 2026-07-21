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
package org.zaproxy.addon.network.internal.server.http.handlers;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.network.HttpRequestConfig;

/** Unit test for {@link BrowserRequestHandler}. */
class BrowserRequestHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpSender httpSender;
    private BrowserRequestHandler.Action action;
    private BrowserRequestHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        httpSender = mock(HttpSender.class);
        action = BrowserRequestHandler.Action.HIDE;
        handler = new BrowserRequestHandler(() -> action, httpSender);
    }

    @Test
    void shouldThrowIfActionSupplierIsNull() {
        assertThrows(NullPointerException.class, () -> new BrowserRequestHandler(null, httpSender));
    }

    @Test
    void shouldThrowIfHttpSenderIsNull() {
        assertThrows(
                NullPointerException.class, () -> new BrowserRequestHandler(() -> action, null));
    }

    @Test
    void shouldNotHandleResponseMessage() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        action = BrowserRequestHandler.Action.BLOCK;
        HttpMessage message = createKnownRequest("GET");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).overridden();
        verify(httpSender, times(0)).sendAndReceive(any(), any(HttpRequestConfig.class));
        assertThat(message.getResponseHeader().isEmpty(), is(equalTo(true)));
    }

    @ParameterizedTest
    @EnumSource(BrowserRequestHandler.Action.class)
    void shouldDoNothingWhenUriDoesNotMatch(BrowserRequestHandler.Action a) throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = a;
        HttpMessage message = createRequest("GET", "https://not.known.example.org/");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).overridden();
        verify(httpSender, times(0)).sendAndReceive(any(), any(HttpRequestConfig.class));
        assertThat(message.getResponseHeader().isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldDoNothingWhenActionIsNone() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = BrowserRequestHandler.Action.NONE;
        HttpMessage message = createKnownRequest("GET");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).overridden();
        verify(httpSender, times(0)).sendAndReceive(any(), any(HttpRequestConfig.class));
        assertThat(message.getResponseHeader().isEmpty(), is(equalTo(true)));
    }

    @Test
    void shouldReturn403WhenActionIsBlock() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = BrowserRequestHandler.Action.BLOCK;
        HttpMessage message = createKnownRequest("GET");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, atLeastOnce()).overridden();
        verify(httpSender, times(0)).sendAndReceive(any(), any(HttpRequestConfig.class));
        assertThat(message.getResponseHeader().isEmpty(), is(equalTo(false)));
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 403 Forbidden"));
        assertThat(message.getResponseBody().toString(), is(equalTo("Forbidden")));
    }

    @Test
    void shouldNotSetBodyForHeadRequestWhenActionIsBlock() {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = BrowserRequestHandler.Action.BLOCK;
        HttpMessage message = createKnownRequest("HEAD");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, atLeastOnce()).overridden();
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 403 Forbidden"));
        assertThat(message.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldForwardSilentlyWhenActionIsHide() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = BrowserRequestHandler.Action.HIDE;
        HttpMessage message = createKnownRequest("GET");
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, atLeastOnce()).overridden();
        ArgumentCaptor<HttpRequestConfig> configCaptor = ArgumentCaptor.captor();
        verify(httpSender, times(1)).sendAndReceive(eq(message), configCaptor.capture());
        assertThat(configCaptor.getValue().isNotifyListeners(), is(equalTo(false)));
    }

    @Test
    void shouldSetBadGatewayResponseWhenHideThrowsIoException() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        action = BrowserRequestHandler.Action.HIDE;
        HttpMessage message = createKnownRequest("GET");
        doThrow(new IOException("connection refused"))
                .when(httpSender)
                .sendAndReceive(any(), any(HttpRequestConfig.class));
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(ctx, atLeastOnce()).overridden();
        assertThat(message.getResponseHeader().isEmpty(), is(equalTo(false)));
        assertThat(message.getResponseHeader().toString(), startsWith("HTTP/1.1 502 Bad Gateway"));
    }

    private static HttpMessage createKnownRequest(String method) {
        return createRequest(method, "https://archive.mozilla.org/");
    }

    private static HttpMessage createRequest(String method, String uri) {
        try {
            return new HttpMessage(new HttpRequestHeader(method + " " + uri + " HTTP/1.1"));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
