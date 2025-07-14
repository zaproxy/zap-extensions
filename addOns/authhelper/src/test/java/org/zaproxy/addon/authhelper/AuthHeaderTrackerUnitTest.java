/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.User;

class AuthHeaderTrackerUnitTest extends TestUtils {

    private AuthHeaderTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new AuthHeaderTracker();
    }

    @Test
    void shouldIgnoreOptionsMethod() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String token = "Should be ignored";
        msg.setRequestHeader("OPTIONS http://www.example.com/test/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(0)));
        assertAuthorization(msg, token);
    }

    @Test
    void shouldIgnoreNonAuthInitiator() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String token = "Should be ignored";
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.AJAX_SPIDER_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(0)));
        assertAuthorization(msg, token);
    }

    @Test
    void shouldTrackButIgnoreNonAuthRequest() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String token1 = "12345";
        String token2 = "67890";
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2);
        tracker.onHttpRequestSend(msg, HttpSender.AJAX_SPIDER_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(1)));
        assertThat(tracker.getTokenForHost("http://www.example.com"), is(equalTo(token1)));
        assertAuthorization(msg, token2);
    }

    @Test
    void shouldJustTrackLatestToken() throws Exception {
        // Given
        String token1 = "12345";
        String token2 = "45678";
        String token3 = "67890";
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        // When
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2);
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token3);
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(1)));
        assertThat(tracker.getTokenForHost("http://www.example.com"), is(equalTo(token3)));
    }

    @Test
    void shouldTrackTokensAcrossMultipleHosts() throws Exception {
        // Given
        String token1 = "12345";
        HttpMessage msg1 = new HttpMessage();
        msg1.setRequestHeader("GET http://www.example.com:9090/test/ HTTP/1.1");
        msg1.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);
        String token2 = "45678";
        HttpMessage msg2 = new HttpMessage();
        msg2.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg2.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2);
        String token3 = "67890";
        HttpMessage msg3 = new HttpMessage();
        msg3.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg3.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token3);

        // When
        tracker.onHttpRequestSend(msg1, HttpSender.PROXY_INITIATOR, null);
        tracker.onHttpRequestSend(msg2, HttpSender.PROXY_INITIATOR, null);
        tracker.onHttpRequestSend(msg3, HttpSender.PROXY_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(3)));
        assertThat(tracker.getTokenForHost("http://www.example.com:9090"), is(equalTo(token1)));
        assertThat(tracker.getTokenForHost("http://www.example.com"), is(equalTo(token2)));
        assertThat(tracker.getTokenForHost("https://www.example.com"), is(equalTo(token3)));
    }

    @Test
    void shouldClearTokensOnClear() throws Exception {
        // Given
        String token1 = "12345";
        HttpMessage msg1 = new HttpMessage();
        msg1.setRequestHeader("GET http://www.example1.com/test/ HTTP/1.1");
        msg1.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);
        String token2 = "45678";
        HttpMessage msg2 = new HttpMessage();
        msg2.setRequestHeader("GET http://www.example2.com/test/ HTTP/1.1");
        msg2.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2);
        String token3 = "67890";
        HttpMessage msg3 = new HttpMessage();
        msg3.setRequestHeader("GET http://www.example3.com/test/ HTTP/1.1");
        msg3.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token3);

        // When
        tracker.onHttpRequestSend(msg1, HttpSender.PROXY_INITIATOR, null);
        tracker.onHttpRequestSend(msg2, HttpSender.PROXY_INITIATOR, null);
        tracker.onHttpRequestSend(msg3, HttpSender.PROXY_INITIATOR, null);
        tracker.clear();

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(0)));
    }

    @Test
    void shouldReplaceToken() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String token1 = "12345";
        String token2 = "67890";
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);

        User user = mock(User.class);
        Context context = mock(Context.class);
        given(user.getContext()).willReturn(context);
        HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod sessionMethod =
                new HeaderBasedSessionManagementMethodType().createSessionManagementMethod(-1);
        given(context.getSessionManagementMethod()).willReturn(sessionMethod);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        msg.setRequestingUser(user);
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2);
        tracker.onHttpRequestSend(msg, HttpSender.AJAX_SPIDER_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(1)));
        assertThat(tracker.getTokenForHost("http://www.example.com"), is(equalTo(token1)));
        assertAuthorization(msg, token1);
    }

    @Test
    void shouldAddToken() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        String token1 = "12345";
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);

        User user = mock(User.class);
        Context context = mock(Context.class);
        given(user.getContext()).willReturn(context);
        HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod sessionMethod =
                new HeaderBasedSessionManagementMethodType().createSessionManagementMethod(-1);
        given(context.getSessionManagementMethod()).willReturn(sessionMethod);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        msg.setRequestingUser(user);
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, null);
        tracker.onHttpRequestSend(msg, HttpSender.AJAX_SPIDER_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(1)));
        assertThat(tracker.getTokenForHost("http://www.example.com"), is(equalTo(token1)));
        assertAuthorization(msg, token1);
    }

    private static void assertAuthorization(HttpMessage msg, String token) {
        assertThat(
                msg.getRequestHeader().getHeaderValues(HttpRequestHeader.AUTHORIZATION).size(),
                is(equalTo(1)));
        assertThat(
                msg.getRequestHeader().getHeader(HttpRequestHeader.AUTHORIZATION),
                is(equalTo(token)));
    }
}
