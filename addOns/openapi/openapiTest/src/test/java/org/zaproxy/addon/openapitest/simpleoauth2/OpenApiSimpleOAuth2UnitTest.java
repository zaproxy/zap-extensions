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
package org.zaproxy.addon.openapitest.simpleoauth2;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.ExtensionDev;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.ExtensionNetwork;

/** Unit test for the token and test API pages of {@link OpenApiSimpleOAuth2Dir}. */
class OpenApiSimpleOAuth2UnitTest {

    private static final String BASIC =
            "Basic "
                    + Base64.getEncoder()
                            .encodeToString(
                                    "test-client:test-secret".getBytes(StandardCharsets.UTF_8));

    private final TestProxyServer server =
            new TestProxyServer(mock(ExtensionDev.class), mock(ExtensionNetwork.class));
    private final OpenApiSimpleOAuth2Dir dir = new OpenApiSimpleOAuth2Dir(server, "simple-oauth2");

    @Test
    void shouldIssueTokenForValidPasswordGrant() throws Exception {
        // Given
        HttpMessage msg =
                tokenRequest(
                        BASIC, "grant_type=password&username=test@test.com&password=password123");
        // When
        token().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
        assertThat(msg.getResponseBody().toString(), containsString("access_token"));
    }

    @Test
    void shouldAcceptClientCredentialsInBody() throws Exception {
        // Given
        HttpMessage msg =
                tokenRequest(
                        null,
                        "grant_type=password&username=test@test.com&password=password123"
                                + "&client_id=test-client&client_secret=test-secret");
        // When
        token().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
    }

    @Test
    void shouldRejectInvalidClient() throws Exception {
        // Given
        HttpMessage msg =
                tokenRequest(
                        null, "grant_type=password&username=test@test.com&password=password123");
        // When
        token().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(401));
    }

    @Test
    void shouldRejectInvalidPassword() throws Exception {
        // Given
        HttpMessage msg =
                tokenRequest(BASIC, "grant_type=password&username=test@test.com&password=bad");
        // When
        token().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(400));
        assertThat(msg.getResponseBody().toString(), containsString("invalid_grant"));
    }

    @Test
    void shouldRejectOtherGrants() throws Exception {
        // Given
        HttpMessage msg = tokenRequest(BASIC, "grant_type=client_credentials");
        // When
        token().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(400));
    }

    @Test
    void shouldAllowTestApiWithIssuedToken() throws Exception {
        // Given
        HttpMessage tokenMsg =
                tokenRequest(
                        BASIC, "grant_type=password&username=test@test.com&password=password123");
        token().handleMessage(null, tokenMsg);
        String accessToken =
                JSONObject.fromObject(tokenMsg.getResponseBody().toString())
                        .getString("access_token");
        HttpMessage msg = apiRequest("Bearer " + accessToken);
        // When
        api().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(200));
    }

    @Test
    void shouldRejectTestApiWithoutValidToken() throws Exception {
        // Given
        HttpMessage msg = apiRequest("Bearer unknown");
        // When
        api().handleMessage(null, msg);
        // Then
        assertThat(msg.getResponseHeader().getStatusCode(), is(401));
    }

    private OpenApiOAuth2TokenPage token() {
        return new OpenApiOAuth2TokenPage(server) {
            @Override
            public OpenApiSimpleOAuth2Dir getParent() {
                return dir;
            }
        };
    }

    private OpenApiOAuth2TestApiPage api() {
        return new OpenApiOAuth2TestApiPage(server) {
            @Override
            public OpenApiSimpleOAuth2Dir getParent() {
                return dir;
            }
        };
    }

    private static HttpMessage tokenRequest(String authorization, String body) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("POST http://localhost/token HTTP/1.1");
        msg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
        if (authorization != null) {
            msg.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, authorization);
        }
        msg.setRequestBody(body);
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        return msg;
    }

    private static HttpMessage apiRequest(String authorization) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://localhost/test-api HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.AUTHORIZATION, authorization);
        return msg;
    }
}
