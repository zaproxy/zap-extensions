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
package org.zaproxy.addon.dev.csrf.basic;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;

/** Unit test for the CSRF token of the pages of {@link BasicCsrfDir}, which is reset. */
class BasicCsrfDirUnitTest {

    private static final Pattern TOKEN = Pattern.compile("token=([0-9a-f-]{36})");

    private BasicCsrfDir dir;
    private TestPage page;

    @BeforeEach
    void setUp() {
        TestProxyServer server = mock(TestProxyServer.class);
        given(server.getTextFile(any(TestDirectory.class), eq("page.html")))
                .willReturn("<!-- TABLE -->token=<!-- CSRF -->");
        given(server.getTextFile(any(TestDirectory.class), eq("bad-token.html")))
                .willReturn("bad token");
        dir = new BasicCsrfDir(server, "csrf");
        // A page is in the deepest directories.
        page = dir.getSubDir("0").getSubDir("0").getPage("page");
    }

    @Test
    void shouldAcceptTokenFromPage() throws Exception {
        // Given
        String token = tokenFrom(send(get()));
        // When
        HttpMessage response = send(post(token));
        // Then
        assertThat(response.getResponseHeader().getStatusCode(), is(equalTo(200)));
    }

    @Test
    void shouldRejectTokenFromPageOnceReset() throws Exception {
        // Given
        String token = tokenFrom(send(get()));

        // When
        dir.reset();
        HttpMessage response = send(post(token));

        // Then
        assertThat(response.getResponseHeader().getStatusCode(), is(equalTo(403)));
    }

    private HttpMessage send(HttpMessage msg) {
        page.handleMessage(null, msg);
        return msg;
    }

    private static HttpMessage get() throws Exception {
        return new HttpMessage(
                new HttpRequestHeader("GET /csrf/0/0/page HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    }

    private static HttpMessage post(String token) throws Exception {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "POST /csrf/0/0/page HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
        msg.setRequestBody("csrf_token=" + token);
        return msg;
    }

    private static String tokenFrom(HttpMessage response) {
        Matcher matcher = TOKEN.matcher(response.getResponseBody().toString());
        assertThat("No token in the page", matcher.find(), is(equalTo(true)));
        return matcher.group(1);
    }
}
