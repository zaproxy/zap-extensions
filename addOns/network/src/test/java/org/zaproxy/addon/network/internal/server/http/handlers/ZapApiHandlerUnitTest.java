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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

/** Unit test for {@link ZapApiHandler}. */
class ZapApiHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpRequestHeader requestHeader;
    private HttpMessage message;
    private HandlerState state;
    private ZapApiHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        requestHeader = mock(HttpRequestHeader.class);
        message = mock(HttpMessage.class);
        given(message.getRequestHeader()).willReturn(requestHeader);
        state = mock(HandlerState.class);
        given(state.isEnabled()).willReturn(true);
        handler = new ZapApiHandler(state);
    }

    @Test
    void shouldHandleExcludedMessage() throws Exception {
        // Given
        given(ctx.isExcluded()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message).getRequestBody();
    }

    @Test
    void shouldNotHandleResponse() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestHeader();
    }

    @Test
    void shouldNotHandleIfNotEnabled() throws Exception {
        // Given
        given(state.isEnabled()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestHeader();
    }

    @Test
    void shouldNotHandleConnectRequests() throws Exception {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestBody();
    }

    @Test
    void shouldSkipNonApiRequest() throws Exception {
        // Given
        HttpRequestBody requestBody = mock(HttpRequestBody.class);
        given(message.getRequestBody()).willReturn(requestBody);
        given(requestBody.getBytes()).willReturn(new byte[0]);
        API api = mock(API.class);
        // When
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(() -> API.getInstance()).thenReturn(api);
            handler.handleMessage(ctx, message);
        }
        // Then
        verify(api).handleApiRequest(eq(requestHeader), any(), any(), eq(false));
        verify(ctx).isRecursive();
        verify(ctx, times(0)).close();
        verify(ctx, times(0)).overridden();
    }

    @Test
    void shouldCloseConnectionIfRecursiveAndNonApiRequest() throws Exception {
        // Given
        HttpRequestBody requestBody = mock(HttpRequestBody.class);
        given(message.getRequestBody()).willReturn(requestBody);
        given(requestBody.getBytes()).willReturn(new byte[0]);
        given(ctx.isRecursive()).willReturn(true);
        API api = mock(API.class);
        HttpMessage apiResponse = mock(HttpMessage.class);
        HttpRequestHeader apiRequestHeader = mock(HttpRequestHeader.class);
        given(apiRequestHeader.isEmpty()).willReturn(true);
        given(apiResponse.getRequestHeader()).willReturn(apiRequestHeader);
        given(api.handleApiRequest(any(), any(), any(), anyBoolean())).willReturn(apiResponse);
        // When
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(() -> API.getInstance()).thenReturn(api);
            handler.handleMessage(ctx, message);
        }
        // Then
        verify(api).handleApiRequest(eq(requestHeader), any(), any(), eq(true));
        verify(ctx).isRecursive();
        verify(ctx).close();
        verify(ctx, times(0)).overridden();
    }

    @Test
    void shouldCloseConnectionOnApiException() throws Exception {
        // Given
        HttpRequestBody requestBody = mock(HttpRequestBody.class);
        given(message.getRequestBody()).willReturn(requestBody);
        given(requestBody.getBytes()).willReturn(new byte[0]);
        API api = mock(API.class);
        given(api.handleApiRequest(any(), any(), any(), anyBoolean())).willThrow(IOException.class);
        // When
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(() -> API.getInstance()).thenReturn(api);
            handler.handleMessage(ctx, message);
        }
        // Then
        verify(api).handleApiRequest(eq(requestHeader), any(), any(), eq(false));
        verify(ctx).close();
    }

    @Test
    void shouldHandleApiRequest() throws Exception {
        // Given
        HttpRequestBody requestBody = mock(HttpRequestBody.class);
        given(message.getRequestBody()).willReturn(requestBody);
        given(requestBody.getBytes()).willReturn(new byte[0]);
        API api = mock(API.class);
        HttpMessage apiResponse = mock(HttpMessage.class);
        HttpRequestHeader apiRequestHeader = mock(HttpRequestHeader.class);
        given(apiRequestHeader.isEmpty()).willReturn(false);
        given(apiResponse.getRequestHeader()).willReturn(apiRequestHeader);
        HttpResponseHeader apiResponseHeader = mock(HttpResponseHeader.class);
        given(apiResponse.getResponseHeader()).willReturn(apiResponseHeader);
        HttpResponseBody apiResponseBody = mock(HttpResponseBody.class);
        given(apiResponse.getResponseBody()).willReturn(apiResponseBody);
        given(api.handleApiRequest(any(), any(), any(), anyBoolean())).willReturn(apiResponse);
        // When
        try (MockedStatic<API> apiStatic = mockStatic(API.class)) {
            apiStatic.when(() -> API.getInstance()).thenReturn(api);
            handler.handleMessage(ctx, message);
        }
        // Then
        verify(api).handleApiRequest(eq(requestHeader), any(), any(), eq(false));
        verify(ctx).isRecursive();
        verify(ctx, times(0)).close();
        verify(ctx).overridden();
        verify(message).setResponseHeader(apiResponseHeader);
        verify(message).setResponseBody(apiResponseBody);
    }
}
