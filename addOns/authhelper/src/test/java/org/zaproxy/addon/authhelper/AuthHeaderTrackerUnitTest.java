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
        assertHeaderSent(msg, token);
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
        assertTrackedHeader("http://www.example.com", HttpRequestHeader.AUTHORIZATION, null);
        assertHeaderSent(msg, token);
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
        assertTrackedHeader("http://www.example.com", HttpRequestHeader.AUTHORIZATION, token1);
        assertHeaderSent(msg, token2);
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
        assertTrackedHeader("http://www.example.com", HttpRequestHeader.AUTHORIZATION, token3);
    }

    @Test
    void shouldTrackTokensAcrossMultipleHosts() throws Exception {
        // Given
        String token1 = "12345";
        HttpMessage msg1 = new HttpMessage();
        msg1.setRequestHeader("GET http://www.example.com:9090/test/ HTTP/1.1");
        msg1.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1 + "1");
        msg1.getRequestHeader().setHeader("CustomAuth", token1 + "2");
        msg1.getRequestHeader().setHeader("CSRF-Token", token1 + "3");
        String token2 = "45678";
        HttpMessage msg2 = new HttpMessage();
        msg2.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        msg2.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2 + "1");
        msg2.getRequestHeader().setHeader("auTh", token2 + "2");
        msg2.getRequestHeader().setHeader("CSRF", token2 + "3");
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
        assertTrackedHeader(
                "http://www.example.com:9090", HttpRequestHeader.AUTHORIZATION, token1 + "1");
        assertTrackedHeader("http://www.example.com:9090", "CustomAuth", token1 + "2");
        assertTrackedHeader("http://www.example.com:9090", "CSRF-Token", token1 + "3");
        assertTrackedHeader(
                "http://www.example.com", HttpRequestHeader.AUTHORIZATION, token2 + "1");
        assertTrackedHeader("http://www.example.com", "AUTH", token2 + "2");
        assertTrackedHeader("http://www.example.com", "csrf", token2 + "3");
        assertTrackedHeader("https://www.example.com", HttpRequestHeader.AUTHORIZATION, token3);
    }

    @Test
    void shouldClearTokensOnClear() throws Exception {
        // Given
        String token1 = "12345";
        HttpMessage msg1 = new HttpMessage();
        msg1.setRequestHeader("GET http://www.example1.com/test/ HTTP/1.1");
        msg1.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1);
        msg1.getRequestHeader().setHeader("CSRF-Token", token1 + "2");
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
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token1 + "A");
        msg.getRequestHeader().setHeader("Custom-CSRF", token1 + "B");

        User user = mock(User.class);
        Context context = mock(Context.class);
        given(user.getContext()).willReturn(context);
        HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod sessionMethod =
                new HeaderBasedSessionManagementMethodType().createSessionManagementMethod(-1);
        given(context.getSessionManagementMethod()).willReturn(sessionMethod);

        // When
        tracker.onHttpRequestSend(msg, HttpSender.PROXY_INITIATOR, null);

        msg.setRequestingUser(user);
        msg.getRequestHeader().setHeader(HttpRequestHeader.AUTHORIZATION, token2 + "A");
        msg.getRequestHeader().setHeader("Custom-CSRF", token2 + "B");
        tracker.onHttpRequestSend(msg, HttpSender.AJAX_SPIDER_INITIATOR, null);

        // Then
        assertThat(tracker.getHostCount(), is(equalTo(1)));
        assertTrackedHeader(
                "http://www.example.com", HttpRequestHeader.AUTHORIZATION, token1 + "A");
        assertTrackedHeader("http://www.example.com", "custom-CSRF", token1 + "B");
        assertHeaderSent(msg, token1 + "A");
        assertHeaderSent(msg, "Custom-CSRF", token1 + "B");
    }

    @Test
    void shouldAddToken() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        // Use a fairly long token, just to make sure its not trimmed
        String token1 =
                "1234573489076098452766420973-4987246096702340968709687394044654862306428467267403972409247609247";
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
        assertTrackedHeader("http://www.example.com", HttpRequestHeader.AUTHORIZATION, token1);
        assertHeaderSent(msg, token1);
    }

    private void assertTrackedHeader(String site, String header, String value) {
        assertThat(tracker.getTokenForHost(site, header), is(equalTo(value)));
    }

    private static void assertHeaderSent(HttpMessage msg, String token) {
        assertHeaderSent(msg, HttpRequestHeader.AUTHORIZATION, token);
    }

    private static void assertHeaderSent(HttpMessage msg, String header, String token) {
        assertThat(msg.getRequestHeader().getHeaderValues(header).size(), is(equalTo(1)));
        assertThat(msg.getRequestHeader().getHeader(header), is(equalTo(token)));
    }
}
