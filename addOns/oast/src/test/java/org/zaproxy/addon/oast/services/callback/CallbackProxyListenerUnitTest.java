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
package org.zaproxy.addon.oast.services.callback;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.Stats;

/* Unit test for {@link CallbackProxyListener}. */
class CallbackProxyListenerUnitTest extends TestUtils {

    private static final String EXPECTED_RESPONSE_HEADER =
            "HTTP/1.1 200\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    private HttpMessage message;
    private InetAddress source;
    private OastRequest oastRequest;
    private OastRequestFactory oastRequestFactory;
    private CallbackService callbackService;
    private HttpMessageHandlerContext ctx;
    private CallbackProxyListener listener;

    @BeforeAll
    static void setupAll() {
        mockMessages(new ExtensionOast());
    }

    @BeforeEach
    void setup() throws Exception {
        message = new HttpMessage(new HttpRequestHeader("GET /uuid HTTP/1.1\r\n"));
        source = InetAddress.getLocalHost();
        message.getRequestHeader().setSenderAddress(source);
        oastRequest = mock(OastRequest.class);
        oastRequestFactory = mock(OastRequestFactory.class, withSettings().lenient());
        given(oastRequestFactory.create(any(), anyString(), anyString())).willReturn(oastRequest);
        callbackService = mock(CallbackService.class);
        ctx = mock(HttpMessageHandlerContext.class);
        listener = new CallbackProxyListener(callbackService, oastRequestFactory);
    }

    @Test
    void shouldThrowForNullCallbackService() throws Exception {
        // Given
        CallbackService callbackService = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CallbackProxyListener(callbackService, oastRequestFactory));
    }

    @Test
    void shouldThrowForNullOastRequestFactory() throws Exception {
        // Given
        OastRequestFactory oastRequestFactory = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CallbackProxyListener(callbackService, oastRequestFactory));
    }

    @Test
    void shouldNotifyOfRequestReceivedForUnknownCallbackHandler() throws Exception {
        // Given
        long now = System.currentTimeMillis();
        given(ctx.isFromClient()).willReturn(true);
        // When
        listener.handleMessage(ctx, message);
        // Then
        verify(ctx).overridden();
        assertMessage(now);
        verifyServiceAndFactory("No callback handler");
    }

    @Test
    void shouldNotifyOfRequestReceivedForKnownCallbackHandler() throws Exception {
        // Given
        long now = System.currentTimeMillis();
        String handler = "Known Handler";
        Map<String, String> handlers = new HashMap<>();
        handlers.put("uuid", handler);
        given(callbackService.getHandlers()).willReturn(handlers);
        given(ctx.isFromClient()).willReturn(true);
        // When
        listener.handleMessage(ctx, message);
        // Then
        verify(ctx).overridden();
        assertMessage(now);
        verifyServiceAndFactory(handler);
    }

    @Test
    void shouldNotNotifyOfResponse() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(false);
        // When
        listener.handleMessage(ctx, message);
        // Then
        verify(ctx, times(0)).overridden();
        verify(callbackService, times(0)).handleOastRequest(oastRequest);
    }

    @Test
    void shouldIncrementStatInteractionsCorrectly() throws Exception {
        // Given
        given(ctx.isFromClient()).willReturn(true);
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        // When
        listener.handleMessage(ctx, message);
        // Then
        assertThat(stats.getStat("stats.oast.callback.interactions"), is(1L));
    }

    private void verifyServiceAndFactory(String handler) throws Exception {
        verify(oastRequestFactory).create(message, source.getHostAddress(), handler);
        verify(callbackService).handleOastRequest(oastRequest);
    }

    private void assertMessage(long time) {
        assertThat(
                message.getTimeSentMillis(),
                is(allOf(greaterThanOrEqualTo(time), lessThanOrEqualTo(time + 1000L))));
        assertThat(message.getResponseHeader().toString(), is(equalTo(EXPECTED_RESPONSE_HEADER)));
    }
}
