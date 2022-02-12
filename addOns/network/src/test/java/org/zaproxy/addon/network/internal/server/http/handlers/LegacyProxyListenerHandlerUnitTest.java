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

import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.Socket;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.parosproxy.paros.core.proxy.ConnectRequestProxyListener;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.PersistentConnectionListener;
import org.zaproxy.zap.ZapGetMethod;

/** Unit test for {@link LegacyProxyListenerHandler}. */
class LegacyProxyListenerHandlerUnitTest {

    private HttpMessageHandlerContext ctx;
    private HttpRequestHeader requestHeader;
    private HttpResponseHeader responseHeader;
    private HttpMessage message;
    private Socket socket;
    private ZapGetMethod method;
    private LegacyProxyListenerHandler handler;

    @BeforeEach
    void setUp() {
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        requestHeader = mock(HttpRequestHeader.class);
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.GET);
        message = mock(HttpMessage.class);
        given(message.getRequestHeader()).willReturn(requestHeader);
        responseHeader = mock(HttpResponseHeader.class);
        given(responseHeader.isEmpty()).willReturn(true);
        given(message.getResponseHeader()).willReturn(responseHeader);
        socket = mock(Socket.class);
        method = mock(ZapGetMethod.class);
        handler = new LegacyProxyListenerHandler();
    }

    static Stream<Arguments> noNotifications() {
        return Stream.of(
                arguments(true, HttpRequestHeader.GET),
                arguments(false, HttpRequestHeader.GET),
                arguments(true, HttpRequestHeader.CONNECT),
                arguments(false, HttpRequestHeader.CONNECT));
    }

    @ParameterizedTest
    @MethodSource("noNotifications")
    void shouldNotNotifyAnyListenerIfMessageExcluded(boolean request, String method) {
        // Given
        given(ctx.isExcluded()).willReturn(true);
        given(ctx.isFromClient()).willReturn(request);
        given(requestHeader.getMethod()).willReturn(method);
        ConnectRequestProxyListener listenerConnect = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listenerConnect);
        OverrideMessageProxyListener listenerOverride = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listenerOverride);
        ProxyListener listenerProxy = mock(ProxyListener.class);
        handler.addProxyListener(listenerProxy);
        PersistentConnectionListener listenerPersistent = mock(PersistentConnectionListener.class);
        handler.addPersistentConnectionListener(listenerPersistent);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listenerConnect, times(0)).receivedConnectRequest(message);
        verify(listenerOverride, times(0)).onHttpRequestSend(message);
        verify(listenerOverride, times(0)).onHttpResponseReceived(message);
        verify(listenerProxy, times(0)).onHttpRequestSend(message);
        verify(listenerProxy, times(0)).onHttpResponseReceive(message);
        verify(listenerPersistent, times(0)).onHandshakeResponse(any(), any(), any());
        assertContext(0, 0);
    }

    private void assertContext(int overridden, int closed) {
        verify(ctx, times(overridden)).overridden();
        verify(ctx, times(closed)).close();
    }

    @Test
    void shouldNotifyConnectRequestProxyListenersOfConnect() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyConnectRequestProxyListenersInAddedOrder() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener1 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener1);
        ConnectRequestProxyListener listener2 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener2);
        ConnectRequestProxyListener listener3 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener3);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).receivedConnectRequest(message);
        inOrder.verify(listener2).receivedConnectRequest(message);
        inOrder.verify(listener3).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotNotifyConnectRequestProxyListenersIfNotConnect() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.HEAD);
        ConnectRequestProxyListener listener = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener, times(0)).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotNotifyConnectRequestProxyListenersIfConnectButResponse() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener, times(0)).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldNotNotifyOtherListenersWhenConnect(boolean request) {
        // Given
        given(ctx.isFromClient()).willReturn(request);
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        OverrideMessageProxyListener listenerOverride = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listenerOverride);
        ProxyListener listenerProxy = mock(ProxyListener.class);
        handler.addProxyListener(listenerProxy);
        PersistentConnectionListener listenerPersistent = mock(PersistentConnectionListener.class);
        handler.addPersistentConnectionListener(listenerPersistent);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listenerOverride, times(0)).onHttpRequestSend(message);
        verify(listenerOverride, times(0)).onHttpResponseReceived(message);
        verify(listenerProxy, times(0)).onHttpRequestSend(message);
        verify(listenerProxy, times(0)).onHttpResponseReceive(message);
        verify(listenerPersistent, times(0)).onHandshakeResponse(any(), any(), any());
        assertContext(0, 0);
    }

    @Test
    void shouldNotOverrideIfConnectRequestProxyListenerChangesResponse() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener);
        given(responseHeader.isEmpty()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCatchConnectRequestProxyListenerExceptionsAndContinueNotification() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener1 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener1);
        ConnectRequestProxyListener listener2 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener2);
        ConnectRequestProxyListener listener3 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener3);
        doThrow(RuntimeException.class).when(listener2).receivedConnectRequest(message);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).receivedConnectRequest(message);
        inOrder.verify(listener2).receivedConnectRequest(message);
        inOrder.verify(listener3).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldRemoveConnectRequestProxyListeners() {
        // Given
        given(requestHeader.getMethod()).willReturn(HttpRequestHeader.CONNECT);
        ConnectRequestProxyListener listener1 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener1);
        ConnectRequestProxyListener listener2 = mock(ConnectRequestProxyListener.class);
        handler.addConnectRequestProxyListener(listener2);
        // When
        handler.removeConnectRequestProxyListener(listener1);
        handler.handleMessage(ctx, message);
        // Then
        verify(listener1, times(0)).receivedConnectRequest(message);
        verify(listener2, times(1)).receivedConnectRequest(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyOverrideMessageProxyListenerOfNonConnectRequests() {
        // Given
        OverrideMessageProxyListener listener = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listener);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener).onHttpRequestSend(message);
        verify(listener, times(0)).onHttpResponseReceived(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyOverrideMessageProxyListenerOfNonConnectResponses() {
        // Given
        OverrideMessageProxyListener listener = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listener);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener, times(0)).onHttpRequestSend(message);
        verify(listener).onHttpResponseReceived(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyOverrideMessageProxyListenersOfRequestInTheirOrder() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(2);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(3);
        handler.addOverrideMessageProxyListener(listener2);
        OverrideMessageProxyListener listener3 = mock(OverrideMessageProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(1);
        handler.addOverrideMessageProxyListener(listener3);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener3).onHttpRequestSend(message);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyOverrideMessageProxyListenersOfResponseInTheirOrder() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(2);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(3);
        handler.addOverrideMessageProxyListener(listener2);
        OverrideMessageProxyListener listener3 = mock(OverrideMessageProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(1);
        handler.addOverrideMessageProxyListener(listener3);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener3).onHttpResponseReceived(message);
        inOrder.verify(listener1).onHttpResponseReceived(message);
        inOrder.verify(listener2).onHttpResponseReceived(message);
        assertContext(0, 0);
    }

    @Test
    void shouldOverrideRequestFromOverrideMessageProxyListener() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpRequestSend(message)).willReturn(true);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2, times(0)).onHttpRequestSend(message);
        assertContext(1, 0);
    }

    @Test
    void shouldOverrideResponseFromOverrideMessageProxyListener() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpResponseReceived(message)).willReturn(true);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpResponseReceived(message);
        inOrder.verify(listener2, times(0)).onHttpResponseReceived(message);
        assertContext(1, 0);
    }

    @Test
    void shouldNotOverrideNorCloseIfResponseNotEmptyAfterOverrideMessageProxyListeners() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        handler.addOverrideMessageProxyListener(listener2);
        given(responseHeader.isEmpty()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCatchOverrideMessageProxyListenerExceptionsAndContinueNotificationOfRequest() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        handler.addOverrideMessageProxyListener(listener2);
        OverrideMessageProxyListener listener3 = mock(OverrideMessageProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(3);
        handler.addOverrideMessageProxyListener(listener3);
        doThrow(RuntimeException.class).when(listener2).onHttpRequestSend(message);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        inOrder.verify(listener3).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCatchOverrideMessageProxyListenerExceptionsAndContinueNotificationOfResponse() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        handler.addOverrideMessageProxyListener(listener2);
        OverrideMessageProxyListener listener3 = mock(OverrideMessageProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(3);
        handler.addOverrideMessageProxyListener(listener3);
        doThrow(RuntimeException.class).when(listener2).onHttpResponseReceived(message);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).onHttpResponseReceived(message);
        inOrder.verify(listener2).onHttpResponseReceived(message);
        inOrder.verify(listener3).onHttpResponseReceived(message);
        assertContext(0, 0);
    }

    @Test
    void shouldRemoveOverrideMessageProxyListeners() {
        // Given
        OverrideMessageProxyListener listener1 = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listener1);
        OverrideMessageProxyListener listener2 = mock(OverrideMessageProxyListener.class);
        handler.addOverrideMessageProxyListener(listener2);
        // When
        handler.removeOverrideMessageProxyListener(listener1);
        handler.handleMessage(ctx, message);
        // Then
        verify(listener1, times(0)).onHttpRequestSend(message);
        verify(listener2, times(1)).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyProxyListenerOfNonConnectRequests() {
        // Given
        ProxyListener listener = mock(ProxyListener.class);
        given(listener.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener).onHttpRequestSend(message);
        verify(listener, times(0)).onHttpResponseReceive(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyProxyListenerOfNonConnectResponses() {
        // Given
        ProxyListener listener = mock(ProxyListener.class);
        given(listener.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        verify(listener, times(0)).onHttpRequestSend(message);
        verify(listener).onHttpResponseReceive(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyProxyListenersOfRequestInTheirOrder() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(2);
        given(listener1.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(3);
        given(listener2.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener2);
        ProxyListener listener3 = mock(ProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(1);
        given(listener3.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener3);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener3).onHttpRequestSend(message);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        verify(listener1, times(0)).onHttpResponseReceive(message);
        verify(listener2, times(0)).onHttpResponseReceive(message);
        verify(listener3, times(0)).onHttpResponseReceive(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyProxyListenersOfResponseInTheirOrder() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(2);
        given(listener1.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(3);
        given(listener2.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener2);
        ProxyListener listener3 = mock(ProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(1);
        given(listener3.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener3);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener3).onHttpResponseReceive(message);
        inOrder.verify(listener1).onHttpResponseReceive(message);
        inOrder.verify(listener2).onHttpResponseReceive(message);
        verify(listener1, times(0)).onHttpRequestSend(message);
        verify(listener2, times(0)).onHttpRequestSend(message);
        verify(listener3, times(0)).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCloseRequestFromProxyListener() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpRequestSend(message)).willReturn(false);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(listener2.onHttpRequestSend(message)).willReturn(true);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2, times(0)).onHttpRequestSend(message);
        assertContext(0, 1);
    }

    @Test
    void shouldCloseResponseFromProxyListener() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpResponseReceive(message)).willReturn(false);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(listener2.onHttpResponseReceive(message)).willReturn(true);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpResponseReceive(message);
        inOrder.verify(listener2, times(0)).onHttpResponseReceive(message);
        assertContext(0, 1);
    }

    @Test
    void shouldNotOverrideNorCloseIfResponseNotEmptyAfterProxyListeners() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(listener2.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener2);
        given(responseHeader.isEmpty()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCatchProxyListenerExceptionsAndContinueNotificationOfRequest() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(listener2.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener2);
        ProxyListener listener3 = mock(ProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(3);
        given(listener3.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener3);
        doThrow(RuntimeException.class).when(listener2).onHttpRequestSend(message);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).onHttpRequestSend(message);
        inOrder.verify(listener2).onHttpRequestSend(message);
        inOrder.verify(listener3).onHttpRequestSend(message);
        verify(listener1, times(0)).onHttpResponseReceive(message);
        verify(listener2, times(0)).onHttpResponseReceive(message);
        verify(listener3, times(0)).onHttpResponseReceive(message);
        assertContext(0, 0);
    }

    @Test
    void shouldCatchProxyListenerExceptionsAndContinueNotificationOfResponse() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        given(listener2.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener2);
        ProxyListener listener3 = mock(ProxyListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(3);
        given(listener3.onHttpResponseReceive(message)).willReturn(true);
        handler.addProxyListener(listener3);
        doThrow(RuntimeException.class).when(listener2).onHttpResponseReceive(message);
        given(ctx.isFromClient()).willReturn(false);
        // When
        handler.handleMessage(ctx, message);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).onHttpResponseReceive(message);
        inOrder.verify(listener2).onHttpResponseReceive(message);
        inOrder.verify(listener3).onHttpResponseReceive(message);
        verify(listener1, times(0)).onHttpRequestSend(message);
        verify(listener2, times(0)).onHttpRequestSend(message);
        verify(listener3, times(0)).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldRemoveProxyListeners() {
        // Given
        ProxyListener listener1 = mock(ProxyListener.class);
        given(listener1.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener1);
        ProxyListener listener2 = mock(ProxyListener.class);
        given(listener2.onHttpRequestSend(message)).willReturn(true);
        handler.addProxyListener(listener2);
        // When
        handler.removeProxyListener(listener1);
        handler.handleMessage(ctx, message);
        // Then
        verify(listener1, times(0)).onHttpRequestSend(message);
        verify(listener2, times(1)).onHttpRequestSend(message);
        assertContext(0, 0);
    }

    @Test
    void shouldNotifyPersistentConnectionListener() {
        // Given
        PersistentConnectionListener listener = mock(PersistentConnectionListener.class);
        handler.addPersistentConnectionListener(listener);
        // When
        handler.notifyPersistentConnectionListener(message, socket, method);
        // Then
        verify(listener).onHandshakeResponse(message, socket, method);
    }

    @Test
    void shouldNotifyPersistentConnectionListenersInTheirOrder() {
        // Given
        PersistentConnectionListener listener1 = mock(PersistentConnectionListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(2);
        handler.addPersistentConnectionListener(listener1);
        PersistentConnectionListener listener2 = mock(PersistentConnectionListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(3);
        handler.addPersistentConnectionListener(listener2);
        PersistentConnectionListener listener3 = mock(PersistentConnectionListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(1);
        handler.addPersistentConnectionListener(listener3);
        // When
        handler.notifyPersistentConnectionListener(message, socket, method);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener3).onHandshakeResponse(message, socket, method);
        inOrder.verify(listener1).onHandshakeResponse(message, socket, method);
        inOrder.verify(listener2).onHandshakeResponse(message, socket, method);
    }

    @Test
    void shoulKeepOpenForPersistentConnectionListener() {
        // Given
        PersistentConnectionListener listener1 = mock(PersistentConnectionListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        given(listener1.onHandshakeResponse(message, socket, method)).willReturn(true);
        handler.addPersistentConnectionListener(listener1);
        PersistentConnectionListener listener2 = mock(PersistentConnectionListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        // When
        handler.notifyPersistentConnectionListener(message, socket, method);
        // Then
        InOrder inOrder = inOrder(listener1, listener2);
        inOrder.verify(listener1).onHandshakeResponse(message, socket, method);
        inOrder.verify(listener2, times(0)).onHandshakeResponse(message, socket, method);
    }

    @Test
    void shouldCatchPersistentConnectionListenerExceptionsAndContinueNotification() {
        // Given
        PersistentConnectionListener listener1 = mock(PersistentConnectionListener.class);
        given(listener1.getArrangeableListenerOrder()).willReturn(1);
        handler.addPersistentConnectionListener(listener1);
        PersistentConnectionListener listener2 = mock(PersistentConnectionListener.class);
        given(listener2.getArrangeableListenerOrder()).willReturn(2);
        handler.addPersistentConnectionListener(listener2);
        PersistentConnectionListener listener3 = mock(PersistentConnectionListener.class);
        given(listener3.getArrangeableListenerOrder()).willReturn(3);
        handler.addPersistentConnectionListener(listener3);
        doThrow(RuntimeException.class)
                .when(listener2)
                .onHandshakeResponse(message, socket, method);
        // When
        handler.notifyPersistentConnectionListener(message, socket, method);
        // Then
        InOrder inOrder = inOrder(listener1, listener2, listener3);
        inOrder.verify(listener1).onHandshakeResponse(message, socket, method);
        inOrder.verify(listener2).onHandshakeResponse(message, socket, method);
        inOrder.verify(listener3).onHandshakeResponse(message, socket, method);
    }

    @Test
    void shouldRemovePersistentConnectionListeners() {
        // Given
        PersistentConnectionListener listener1 = mock(PersistentConnectionListener.class);
        handler.addPersistentConnectionListener(listener1);
        PersistentConnectionListener listener2 = mock(PersistentConnectionListener.class);
        handler.addPersistentConnectionListener(listener2);
        // When
        handler.removePersistentConnectionListener(listener1);
        handler.notifyPersistentConnectionListener(message, socket, method);
        // Then
        verify(listener1, times(0)).onHandshakeResponse(message, socket, method);
        verify(listener2, times(1)).onHandshakeResponse(message, socket, method);
    }
}
