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
package org.zaproxy.addon.authhelper;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.OAuth2AuthenticationMethodType.OAuth2AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.UnsupportedAuthenticationCredentialsException;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.users.AuthenticationState;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class OAuth2AuthenticationMethodTypeUnitTest {

    @AfterAll
    static void cleanUp() {
        Model.setSingletonForTesting(new Model());
    }

    @Test
    void shouldBeConfiguredThroughTheApi() throws Exception {
        // Given
        ApiDynamicActionImplementor api =
                new OAuth2AuthenticationMethodType().getSetMethodForContextApiAction();
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        int contextId = 1;
        Context context = new Context(session, contextId);
        given(session.getContext(contextId)).willReturn(context);

        JSONObject params = new JSONObject();
        params.put("contextId", contextId);
        params.put("grantType", "client_credentials");
        params.put("tokenEndpoint", "https://example.com/token");
        params.put("clientId", "my-client");
        params.put("clientSecret", "my-secret");
        params.put("clientAuthMethod", "client_secret_post");
        params.put("scope", "read write");
        params.put("accessTokenField", "accessToken");
        params.put("refreshTokenField", "refresh");
        params.put("extraTokenParams", "audience: https://api.example.com");

        // When
        api.handleAction(params);

        // Then
        AuthenticationMethod method = context.getAuthenticationMethod();
        assertThat(method, is(instanceOf(OAuth2AuthenticationMethod.class)));
        OAuth2AuthenticationMethod oauth2 = (OAuth2AuthenticationMethod) method;
        assertThat(oauth2.getGrantType(), is(equalTo("client_credentials")));
        assertThat(oauth2.getTokenEndpoint(), is(equalTo("https://example.com/token")));
        assertThat(oauth2.getClientId(), is(equalTo("my-client")));
        assertThat(oauth2.getClientSecret(), is(equalTo("my-secret")));
        assertThat(oauth2.getClientAuthMethod(), is(equalTo("client_secret_post")));
        assertThat(oauth2.getScope(), is(equalTo("read write")));
        assertThat(oauth2.getAccessTokenField(), is(equalTo("accessToken")));
        assertThat(oauth2.getRefreshTokenField(), is(equalTo("refresh")));
        assertThat(
                oauth2.getExtraTokenParams().get("audience"),
                is(equalTo("https://api.example.com")));
    }

    @Test
    void shouldGetConfigurationThroughTheApi() {
        // Given
        OAuth2AuthenticationMethod method =
                new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
        method.setGrantType("client_credentials");
        method.setTokenEndpoint("https://example.com/token");
        method.setClientId("my-client");
        method.setClientSecret("my-secret");

        // When
        ApiResponse response = method.getApiResponseRepresentation();

        // Then - the secret must never be included in the API representation
        assertThat(response.toJSON().toString(), containsString("\"clientId\":\"my-client\""));
        assertThat(
                response.toJSON().toString(),
                containsString("\"grantType\":\"client_credentials\""));
        assertThat(response.toJSON().toString(), is(not(containsString("my-secret"))));
    }

    @Test
    void shouldPreserveDiagnosticsOnDuplicate() {
        // Given
        OAuth2AuthenticationMethod method =
                new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);

        // When / Then
        assertThat(method.isDiagnostics(), is(equalTo(false)));
        method.setDiagnostics(true);
        assertThat(method.isDiagnostics(), is(equalTo(true)));
        OAuth2AuthenticationMethod copy = (OAuth2AuthenticationMethod) method.duplicate();
        assertThat(copy.isDiagnostics(), is(equalTo(true)));
    }

    @Test
    void shouldExportAndImportData() throws Exception {
        // Given
        OAuth2AuthenticationMethodType type = new OAuth2AuthenticationMethodType();
        OAuth2AuthenticationMethod method1 = type.createAuthenticationMethod(0);
        OAuth2AuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setGrantType("refresh_token");
        method1.setTokenEndpoint("https://example.com/token");
        method1.setClientId("my-client");
        method1.setClientSecret("my-secret");
        method1.setClientAuthMethod("client_secret_post");
        method1.setScope("read");
        method1.setAccessTokenField("accessToken");
        method1.setRefreshTokenField("refresh");
        method1.setExtraTokenParams(Map.of("audience", "https://api.example.com"));
        ZapXmlConfiguration config = new ZapXmlConfiguration();

        // When
        method1.getType().exportData(config, method1);
        method2.getType().importData(config, method2);

        // Then
        assertThat(method2.getGrantType(), is(equalTo("refresh_token")));
        assertThat(method2.getTokenEndpoint(), is(equalTo("https://example.com/token")));
        assertThat(method2.getClientId(), is(equalTo("my-client")));
        assertThat(method2.getClientSecret(), is(equalTo("my-secret")));
        assertThat(method2.getClientAuthMethod(), is(equalTo("client_secret_post")));
        assertThat(method2.getScope(), is(equalTo("read")));
        assertThat(method2.getAccessTokenField(), is(equalTo("accessToken")));
        assertThat(method2.getRefreshTokenField(), is(equalTo("refresh")));
        assertThat(
                method2.getExtraTokenParams().get("audience"),
                is(equalTo("https://api.example.com")));
    }

    @Test
    void shouldPersistAndLoadFromSession() throws Exception {
        // Given
        OAuth2AuthenticationMethodType type = new OAuth2AuthenticationMethodType();
        OAuth2AuthenticationMethod method1 = type.createAuthenticationMethod(0);
        OAuth2AuthenticationMethod method2 = type.createAuthenticationMethod(1);
        method1.setGrantType("password");
        method1.setTokenEndpoint("https://example.com/token");
        method1.setClientId("my-client");
        method1.setClientSecret("my-secret");
        method1.setExtraTokenParams(Map.of("audience", "https://api.example.com"));
        Session session = mock(Session.class);
        ArgumentCaptor<String> valueCapture = ArgumentCaptor.forClass(String.class);

        doNothing()
                .when(session)
                .setContextData(
                        anyInt(),
                        eq(RecordContext.TYPE_AUTH_METHOD_FIELD_1),
                        valueCapture.capture());

        method1.getType().persistMethodToSession(session, 1, method1);

        given(session.getContextDataString(1, RecordContext.TYPE_AUTH_METHOD_FIELD_1, ""))
                .willReturn(valueCapture.getValue());

        // When
        method2 = (OAuth2AuthenticationMethod) method2.getType().loadMethodFromSession(session, 1);

        // Then
        assertThat(method2.getGrantType(), is(equalTo("password")));
        assertThat(method2.getTokenEndpoint(), is(equalTo("https://example.com/token")));
        assertThat(method2.getClientId(), is(equalTo("my-client")));
        assertThat(method2.getClientSecret(), is(equalTo("my-secret")));
        assertThat(
                method2.getExtraTokenParams().get("audience"),
                is(equalTo("https://api.example.com")));
    }

    @Test
    void shouldSetCredentialsThroughTheApi() throws Exception {
        // Given
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        ExtensionUserManagement extUserMgmt = mock(ExtensionUserManagement.class);
        given(extensionLoader.getExtension(ExtensionUserManagement.class)).willReturn(extUserMgmt);
        ContextUserAuthManager userAuthManager = mock(ContextUserAuthManager.class);
        given(extUserMgmt.getContextUserAuthManager(anyInt())).willReturn(userAuthManager);
        User user = mock(User.class);
        given(userAuthManager.getUserById(7)).willReturn(user);

        OAuth2AuthenticationMethodType type = new OAuth2AuthenticationMethodType();
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        int contextId = 1;
        Context context = new Context(session, contextId);
        given(session.getContext(contextId)).willReturn(context);
        context.setAuthenticationMethod(type.createAuthenticationMethod(contextId));

        ApiDynamicActionImplementor api = type.getSetCredentialsForUserApiAction();
        JSONObject params = new JSONObject();
        params.put("contextId", contextId);
        params.put("userId", 7);
        params.put("username", "alice");
        params.put("password", "secret");

        // When
        api.handleAction(params);

        // Then
        ArgumentCaptor<AuthenticationCredentials> captor =
                ArgumentCaptor.forClass(AuthenticationCredentials.class);
        verify(user).setAuthenticationCredentials(captor.capture());
        GenericAuthenticationCredentials creds =
                (GenericAuthenticationCredentials) captor.getValue();
        assertThat(creds.getParam("username"), is(equalTo("alice")));
        assertThat(creds.getParam("password"), is(equalTo("secret")));
        assertThat(creds.getParam("refreshToken"), is(nullValue()));
    }

    @Test
    void shouldRejectNonGenericCredentials() {
        // Given
        OAuth2AuthenticationMethod method =
                new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
        method.setGrantType("client_credentials");
        method.setTokenEndpoint("https://example.com/token");
        SessionManagementMethod sessionManagementMethod = mock(SessionManagementMethod.class);
        User user = mock(User.class);
        given(user.getAuthenticationState()).willReturn(new AuthenticationState());
        AuthenticationCredentials credentials = new UsernamePasswordAuthenticationCredentials();

        // When / Then
        assertThrows(
                UnsupportedAuthenticationCredentialsException.class,
                () -> method.authenticate(sessionManagementMethod, credentials, user));
    }

    private static Map<String, String> parseFormBody(String body) {
        Map<String, String> map = new LinkedHashMap<>();
        if (body.isEmpty()) {
            return map;
        }
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            map.put(
                    URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return map;
    }

    @Nested
    class Authenticate extends TestUtils {

        private String tokenEndpoint;
        private IHTTPSession lastSession;
        private String lastRequestBody;
        private String tokenResponseBody;
        private SessionManagementMethod sessionManagementMethod;
        private WebSession webSession;
        private User user;

        @BeforeEach
        void setupEach() throws Exception {
            startServer();

            String path = "/token";
            tokenEndpoint = "http://localhost:" + nano.getListeningPort() + path;
            tokenResponseBody = "{\"access_token\":\"abc123\",\"expires_in\":3600}";
            nano.addHandler(
                    new NanoServerHandler(path) {
                        @Override
                        protected Response serve(IHTTPSession session) {
                            lastSession = session;
                            lastRequestBody = getBody(session);
                            return newFixedLengthResponse(
                                    Response.Status.OK, "application/json", tokenResponseBody);
                        }
                    });

            Model model = mock(Model.class);
            Session session = mock(Session.class);
            given(model.getSession()).willReturn(session);
            Model.setSingletonForTesting(model);
            Control.initSingletonForTesting(model, mock(ExtensionLoader.class));
            mockMessages(new ExtensionAuthhelper());

            webSession = mock(WebSession.class);
            sessionManagementMethod = mock(SessionManagementMethod.class);
            lenient().when(sessionManagementMethod.extractWebSession(any())).thenReturn(webSession);

            user = mock(User.class);
            given(user.getAuthenticationState()).willReturn(new AuthenticationState());
            Context context = mock(Context.class);
            given(context.getName()).willReturn("context1");
            given(session.getContext("context1")).willReturn(context);
            given(user.getContext()).willReturn(context);
        }

        @AfterEach
        void cleanupEach() {
            stopServer();
        }

        @Test
        void shouldSendClientCredentialsTokenRequestUsingBasicAuth() throws Exception {
            // Given
            OAuth2AuthenticationMethod method =
                    new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
            method.setGrantType("client_credentials");
            method.setTokenEndpoint(tokenEndpoint);
            method.setClientId("my-client");
            method.setClientSecret("my-secret");
            method.setScope("read write");
            AuthenticationCredentials credentials = method.createAuthenticationCredentials();

            // When
            WebSession result = method.authenticate(sessionManagementMethod, credentials, user);

            // Then
            assertThat(result, is(equalTo(webSession)));
            Map<String, String> body = parseFormBody(lastRequestBody);
            assertThat(body.get("grant_type"), is(equalTo("client_credentials")));
            assertThat(body.get("scope"), is(equalTo("read write")));
            assertThat(body.containsKey("client_id"), is(equalTo(false)));
            String authHeader = lastSession.getHeaders().get("authorization");
            assertThat(authHeader, is(equalTo("Basic bXktY2xpZW50Om15LXNlY3JldA==")));
            verify(user).setAuthenticatedSession(webSession);
        }

        @Test
        void shouldSendPasswordGrantTokenRequestUsingPostAuth() throws Exception {
            // Given
            OAuth2AuthenticationMethod method =
                    new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
            method.setGrantType("password");
            method.setTokenEndpoint(tokenEndpoint);
            method.setClientId("my-client");
            method.setClientSecret("my-secret");
            method.setClientAuthMethod(OAuth2AuthenticationMethodType.CLIENT_AUTH_POST);
            GenericAuthenticationCredentials credentials =
                    (GenericAuthenticationCredentials) method.createAuthenticationCredentials();
            credentials.setParam("username", "alice");
            credentials.setParam("password", "s3cret");

            // When
            method.authenticate(sessionManagementMethod, credentials, user);

            // Then
            Map<String, String> body = parseFormBody(lastRequestBody);
            assertThat(body.get("grant_type"), is(equalTo("password")));
            assertThat(body.get("username"), is(equalTo("alice")));
            assertThat(body.get("password"), is(equalTo("s3cret")));
            assertThat(body.get("client_id"), is(equalTo("my-client")));
            assertThat(body.get("client_secret"), is(equalTo("my-secret")));
            assertNull(lastSession.getHeaders().get("authorization"));
        }

        @Test
        void shouldSendRefreshTokenGrantTokenRequestForPublicClient() throws Exception {
            // Given
            OAuth2AuthenticationMethod method =
                    new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
            method.setGrantType("refresh_token");
            method.setTokenEndpoint(tokenEndpoint);
            method.setClientId("my-client");
            method.setClientAuthMethod(OAuth2AuthenticationMethodType.CLIENT_AUTH_NONE);
            GenericAuthenticationCredentials credentials =
                    (GenericAuthenticationCredentials) method.createAuthenticationCredentials();
            credentials.setParam("refreshToken", "rt-123");

            // When
            method.authenticate(sessionManagementMethod, credentials, user);

            // Then
            Map<String, String> body = parseFormBody(lastRequestBody);
            assertThat(body.get("grant_type"), is(equalTo("refresh_token")));
            assertThat(body.get("refresh_token"), is(equalTo("rt-123")));
            assertThat(body.get("client_id"), is(equalTo("my-client")));
            assertThat(body.containsKey("client_secret"), is(equalTo(false)));
            assertNull(lastSession.getHeaders().get("authorization"));
        }

        @Test
        void shouldNormalizeNonStandardTokenFieldNames() throws Exception {
            // Given
            tokenResponseBody = "{\"accessToken\":\"tok1\",\"refresh\":\"ref1\"}";
            OAuth2AuthenticationMethod method =
                    new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
            method.setGrantType("client_credentials");
            method.setTokenEndpoint(tokenEndpoint);
            method.setAccessTokenField("accessToken");
            method.setRefreshTokenField("refresh");
            AuthenticationCredentials credentials = method.createAuthenticationCredentials();

            // When
            method.authenticate(sessionManagementMethod, credentials, user);

            // Then
            ArgumentCaptor<HttpMessage> msgCaptor = ArgumentCaptor.forClass(HttpMessage.class);
            verify(sessionManagementMethod).extractWebSession(msgCaptor.capture());
            JSONObject json =
                    JSONObject.fromObject(msgCaptor.getValue().getResponseBody().toString());
            assertThat(json.getString("accessToken"), is(equalTo("tok1")));
            assertThat(json.getString("refresh"), is(equalTo("ref1")));
            assertThat(json.getString("access_token"), is(equalTo("tok1")));
            assertThat(json.getString("refresh_token"), is(equalTo("ref1")));
        }

        @Test
        void shouldReturnNullWhenTokenEndpointUnreachable() {
            // Given
            OAuth2AuthenticationMethod method =
                    new OAuth2AuthenticationMethodType().createAuthenticationMethod(0);
            method.setGrantType("client_credentials");
            method.setTokenEndpoint("http://localhost:1/token");
            AuthenticationCredentials credentials = method.createAuthenticationCredentials();

            // When
            WebSession result = method.authenticate(sessionManagementMethod, credentials, user);

            // Then
            assertThat(result, is(nullValue()));
        }
    }
}
