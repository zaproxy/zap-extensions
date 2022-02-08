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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.extension.api.API;

/** Unit test for {@link AliasApiRewriteHandler}. */
class AliasApiRewriteHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpRequestHeader requestHeader;
    private HttpMessage message;
    private LocalServerConfig serverConfig;
    private AliasApiRewriteHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        requestHeader = mock(HttpRequestHeader.class);
        message = mock(HttpMessage.class);
        given(message.getRequestHeader()).willReturn(requestHeader);
        serverConfig = mock(LocalServerConfig.class);
        given(serverConfig.isApiEnabled()).willReturn(true);
        handler = new AliasApiRewriteHandler(serverConfig);
    }

    @Test
    void shouldNotHandleExcludedMessage() throws Exception {
        // Given
        given(ctx.isExcluded()).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(message, times(0)).getRequestHeader();
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
    void shouldNotHandleIfApiNotEnabled() throws Exception {
        // Given
        given(serverConfig.isApiEnabled()).willReturn(false);
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
        verify(serverConfig, times(0)).isAlias(any());
    }

    @Test
    void shouldNotRewriteNonAliasRequests() throws Exception {
        // Given
        given(serverConfig.isAlias(any())).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(serverConfig).isAlias(requestHeader);
        verify(requestHeader, times(0)).setHeader(any(), any());
    }

    @Test
    void shouldRewriteAliasRequests() throws Exception {
        // Given
        given(serverConfig.isAlias(any())).willReturn(true);
        URI uri = mock(URI.class);
        given(requestHeader.getURI()).willReturn(uri);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(serverConfig).isAlias(requestHeader);
        verify(uri).setEscapedAuthority(API.API_DOMAIN);
        verify(requestHeader).setHeader(HttpRequestHeader.HOST, API.API_DOMAIN);
    }
}
