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
package org.zaproxy.addon.dev;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for the handling of the requests for the fake domains by {@link TestProxyServer}. */
class TestProxyServerUnitTest {

    private static final String DOMAIN = "https://handled.zap";

    @TempDir Path baseDir;

    private TestProxyServer server;

    @BeforeEach
    void setUp() {
        ExtensionDev extension = mock(ExtensionDev.class);
        DevParam param = mock(DevParam.class);
        given(extension.getDevParam()).willReturn(param);
        given(param.getBaseDirectory()).willReturn(baseDir.toString());
        server = new TestProxyServer(extension, mock(ExtensionNetwork.class));
    }

    @Test
    void shouldPassRedirectedRequestToHandlerOfOriginalDomainAsOriginallySent() throws Exception {
        // Given
        List<String> seen = new ArrayList<>();
        server.addDomainHandler(
                DOMAIN,
                msg -> {
                    seen.add(msg.getRequestHeader().getURI().toString());
                    seen.add(msg.getRequestHeader().getHeader("host"));
                    msg.setResponseHeader(
                            TestProxyServer.getDefaultResponseHeader("text/plain", 0));
                });
        HttpMessage msg = redirectedRequest(DOMAIN + "/a/page?q=1");

        // When
        boolean handled = server.handleDomainRequest(msg);

        // Then
        assertThat(handled, is(equalTo(true)));
        assertThat(seen, is(equalTo(List.of(DOMAIN + "/a/page?q=1", "handled.zap"))));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(200)));
    }

    @Test
    void shouldKeepEscapedParametersWhenPassingRequestToHandler() throws Exception {
        // Given
        List<String> seen = new ArrayList<>();
        server.addDomainHandler(
                DOMAIN,
                msg -> {
                    seen.add(DevUtils.getUrlParam(msg, "redirect_uri"));
                    seen.add(msg.getRequestHeader().getURI().getEscapedQuery());
                });
        HttpMessage msg =
                redirectedRequest(
                        DOMAIN + "/page?redirect_uri=https%3A%2F%2Fapp.zap%2Fcallback.html&a=b+c");

        // When
        server.handleDomainRequest(msg);

        // Then
        assertThat(
                seen,
                is(
                        equalTo(
                                List.of(
                                        "https://app.zap/callback.html",
                                        "redirect_uri=https%3A%2F%2Fapp.zap%2Fcallback.html&a=b+c"))));
    }

    @Test
    void shouldNotHandleRequestsNotRedirected() throws Exception {
        // Given
        server.addDomainHandler(DOMAIN, msg -> msg.setResponseBody("handled"));
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader("GET /page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));

        // When
        boolean handled = server.handleDomainRequest(msg);

        // Then
        assertThat(handled, is(equalTo(false)));
        assertThat(msg.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldNotHandleRequestsForDomainsWithoutHandler() throws Exception {
        // Given
        server.addDomainHandler(DOMAIN, msg -> msg.setResponseBody("handled"));
        HttpMessage msg = redirectedRequest("https://other.zap/page");

        // When
        boolean handled = server.handleDomainRequest(msg);

        // Then
        assertThat(handled, is(equalTo(false)));
        assertThat(msg.getResponseBody().toString(), is(equalTo("")));
    }

    @Test
    void shouldRespondWithServerErrorWhenHandlerFails() throws Exception {
        // Given
        server.addDomainHandler(
                DOMAIN,
                msg -> {
                    throw new IllegalStateException("test");
                });
        HttpMessage msg = redirectedRequest(DOMAIN + "/page");

        // When
        boolean handled = server.handleDomainRequest(msg);

        // Then
        assertThat(handled, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(500)));
    }

    @Test
    void shouldRespondWithNotFoundWhenHandlerDoesNotRespond() throws Exception {
        // Given
        server.addDomainHandler(DOMAIN, msg -> {});
        HttpMessage msg = redirectedRequest(DOMAIN + "/unknown");

        // When
        boolean handled = server.handleDomainRequest(msg);

        // Then
        assertThat(handled, is(equalTo(true)));
        assertThat(msg.getResponseHeader().getStatusCode(), is(equalTo(404)));
    }

    /** A request as it is when it reaches the server, having been redirected to it. */
    private static HttpMessage redirectedRequest(String originalUrl) throws Exception {
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET https://127.0.0.1:9091/a/page HTTP/1.1\r\nHost: 127.0.0.1:9091\r\n\r\n"));
        msg.getRequestHeader().setHeader("zap-dev-sso", originalUrl);
        return msg;
    }
}
