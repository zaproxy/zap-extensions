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
package org.zaproxy.addon.mcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link McpHttpMessageHandler}. */
class McpHttpMessageHandlerUnitTest {

    private McpParam param;
    private McpToolRegistry toolRegistry;
    private McpResourceRegistry resourceRegistry;
    private McpHttpMessageHandler handler;
    private HttpMessageHandlerContext ctx;
    private HttpMessage msg;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ROOT);
        param = new McpParam();
        param.load(new ZapXmlConfiguration());
        param.setSecureOnly(false);
        toolRegistry = new McpToolRegistry();
        toolRegistry.registerTool(new org.zaproxy.addon.mcp.tools.ZapVersionTool());
        resourceRegistry = new McpResourceRegistry();
        handler =
                new McpHttpMessageHandler(
                        param, toolRegistry, resourceRegistry, new McpPromptRegistry(), "");
        ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(true);
        msg = createPostMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");
    }

    @Test
    void shouldAllowRequestWhenSecurityKeyDisabled() throws Exception {
        param.setSecurityKeyEnabled(false);
        param.setSecurityKey("secret");

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
        assertThat(msg.getResponseBody().toString(), containsString("\"result\""));
    }

    @Test
    void shouldRejectRequestWhenSecurityKeyRequiredAndMissing() throws Exception {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("correct-key");

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.UNAUTHORIZED));
        assertThat(msg.getResponseBody().toString(), containsString("security key"));
    }

    @Test
    void shouldRejectRequestWhenSecurityKeyRequiredAndWrong() throws Exception {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("correct-key");
        msg.getRequestHeader().setHeader("Authorization", "wrong-key");

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.UNAUTHORIZED));
    }

    @Test
    void shouldAllowRequestWhenSecurityKeyCorrect() throws Exception {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("correct-key");
        msg.getRequestHeader().setHeader("Authorization", "correct-key");

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
        assertThat(msg.getResponseBody().toString(), containsString("\"result\""));
    }

    @Test
    void shouldAllowRequestWithTrimmedAuthorizationHeader() throws Exception {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("correct-key");
        msg.getRequestHeader().setHeader("Authorization", "  correct-key  ");

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
    }

    @Test
    void shouldHandleOptionsRequest() throws Exception {
        HttpMessage optionsMsg = new HttpMessage();
        optionsMsg.setRequestHeader("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n");

        handler.handleMessage(ctx, optionsMsg);

        assertThat(optionsMsg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
        assertThat(
                optionsMsg.getResponseHeader().getHeader("Access-Control-Allow-Origin"),
                equalTo("*"));
    }

    @Test
    void shouldReturnMethodNotAllowedForUnsupportedMethod() throws Exception {
        param.setSecurityKeyEnabled(false);
        HttpMessage putMsg = new HttpMessage();
        putMsg.setRequestHeader("PUT / HTTP/1.1\r\nHost: localhost\r\n\r\n");

        handler.handleMessage(ctx, putMsg);

        assertThat(
                putMsg.getResponseHeader().getStatusCode(),
                equalTo(HttpStatusCode.METHOD_NOT_ALLOWED));
    }

    @Test
    void shouldReturnBadRequestForEmptyBody() throws Exception {
        param.setSecurityKeyEnabled(false);
        HttpMessage emptyMsg = new HttpMessage();
        emptyMsg.setRequestHeader(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");

        handler.handleMessage(ctx, emptyMsg);

        assertThat(
                emptyMsg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.BAD_REQUEST));
    }

    @Test
    void shouldReturn202ForNotificationsInitialized() throws Exception {
        param.setSecurityKeyEnabled(false);
        HttpMessage notifMsg =
                createPostMessage("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");

        handler.handleMessage(ctx, notifMsg);

        assertThat(notifMsg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.ACCEPTED));
    }

    @Test
    void shouldRejectHttpRequestWhenSecureOnly() throws Exception {
        param.setSecurityKeyEnabled(false);
        param.setSecureOnly(true);

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.FORBIDDEN));
        assertThat(msg.getResponseBody().toString(), containsString("HTTPS"));
    }

    @Test
    void shouldAllowHttpsRequestWhenSecureOnly() throws Exception {
        param.setSecurityKeyEnabled(false);
        param.setSecureOnly(true);
        HttpMessage secureMsg =
                createSecurePostMessage("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}");

        handler.handleMessage(ctx, secureMsg);

        assertThat(secureMsg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
    }

    @Test
    void shouldAllowHttpRequestWhenSecureOnlyDisabled() throws Exception {
        param.setSecurityKeyEnabled(false);
        param.setSecureOnly(false);

        handler.handleMessage(ctx, msg);

        assertThat(msg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
    }

    @Test
    void shouldAllowOptionsRequestOverHttpEvenWhenSecureOnly() throws Exception {
        param.setSecureOnly(true);
        HttpMessage optionsMsg = new HttpMessage();
        optionsMsg.setRequestHeader("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n");

        handler.handleMessage(ctx, optionsMsg);

        assertThat(optionsMsg.getResponseHeader().getStatusCode(), equalTo(HttpStatusCode.OK));
    }

    private static HttpMessage createPostMessage(String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        String header =
                "POST / HTTP/1.1\r\n"
                        + "Host: localhost\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: "
                        + body.length()
                        + "\r\n\r\n";
        msg.setRequestHeader(header);
        msg.setRequestBody(body);
        return msg;
    }

    private static HttpMessage createSecurePostMessage(String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        String header =
                "POST https://localhost/ HTTP/1.1\r\n"
                        + "Host: localhost\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Content-Length: "
                        + body.length()
                        + "\r\n\r\n";
        msg.setRequestHeader(new HttpRequestHeader(header, true));
        msg.setRequestBody(body);
        return msg;
    }
}
