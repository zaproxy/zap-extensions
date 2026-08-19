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
package org.zaproxy.addon.dev.auth.oauth2;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.dev.DevHttpSenderListener;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestAuthDirectory;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;

/**
 * A mock OAuth2 authorization server and relying-party app, used to test all of the non-interactive
 * and interactive OAuth2 authentication methods. It uses multiple domains:
 *
 * <ul>
 *   <li>authserver.oauth2.zap The mock Authorization Server: {@code GET/POST /authorize} (login and
 *       consent) and {@code POST /token} (all 4 grant types: {@code authorization_code} with
 *       optional PKCE, {@code client_credentials}, {@code password}, {@code refresh_token}).
 *   <li>api.oauth2.zap A protected resource server, exposing {@code GET /userinfo}.
 *   <li>app.oauth2.zap A demo relying-party app, for manually exercising the browser-based
 *       authorization_code + PKCE flow independently of ZAP.
 * </ul>
 *
 * <p>Test clients:
 *
 * <ul>
 *   <li>{@code test-client} / {@code test-secret} - confidential client, for {@code
 *       client_secret_basic}/{@code client_secret_post}.
 *   <li>{@code test-public-client} (no secret) - public client, for {@code client_auth_method:
 *       none} (typically together with PKCE).
 * </ul>
 *
 * <p>Test user (shared with the other auth test apps): {@code test@test.com} / {@code password123}.
 */
public class OAuth2RootDir extends TestAuthDirectory {

    private static final Logger LOGGER = LogManager.getLogger(OAuth2RootDir.class);

    private static final String CONFIDENTIAL_CLIENT_ID = "test-client";
    private static final String CONFIDENTIAL_CLIENT_SECRET = "test-secret";
    private static final String PUBLIC_CLIENT_ID = "test-public-client";

    private static final String STATUS_BAD_REQUEST = "400 Bad Request";
    private static final String STATUS_UNAUTHORIZED = "401 Unauthorized";

    private static final long AUTH_CODE_TTL_MILLIS = TimeUnit.MINUTES.toMillis(5);

    private final Map<String, AuthCode> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, String> refreshTokenToUser = new ConcurrentHashMap<>();

    public OAuth2RootDir(TestProxyServer server, String name) {
        super(server, name);
        server.addDomainListener(
                "https://authserver.oauth2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            String page = getPageName(msg);
                            if ("authorize".equals(page)) {
                                handleAuthorize(msg);
                            } else if ("token".equals(page)
                                    && HttpRequestHeader.POST.equals(
                                            msg.getRequestHeader().getMethod())) {
                                handleToken(msg);
                            }
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://api.oauth2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            handleUserInfo(msg);
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
        server.addDomainListener(
                "https://app.oauth2.zap",
                new DevHttpSenderListener(this.getServer()) {
                    @Override
                    public void onHttpResponseReceive(
                            HttpMessage msg, int initiator, HttpSender sender) {
                        try {
                            if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())) {
                                return;
                            }
                            String page = getPageName(msg);
                            if (TestDirectory.INDEX_PAGE.equals(page)) {
                                setHtmlResponse(msg, "app.html");
                            } else if ("callback.html".equals(page)) {
                                setHtmlResponse(msg, "callback.html");
                            }
                        } catch (Exception e) {
                            LOGGER.error(e.getMessage(), e);
                        }
                    }
                });
    }

    private void handleAuthorize(HttpMessage msg) throws Exception {
        boolean isPost = HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod());

        String clientId = getParam(msg, isPost, "client_id");
        String redirectUri = getParam(msg, isPost, "redirect_uri");
        String responseType = getParam(msg, isPost, "response_type");
        String scope = getParam(msg, isPost, "scope");
        String state = getParam(msg, isPost, "state");
        String codeChallenge = getParam(msg, isPost, "code_challenge");
        String codeChallengeMethod = getParam(msg, isPost, "code_challenge_method");

        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(redirectUri)) {
            setErrorResponse(msg, "Missing client_id or redirect_uri");
            return;
        }
        if (StringUtils.isNotEmpty(responseType) && !"code".equals(responseType)) {
            setErrorResponse(msg, "Unsupported response_type: " + responseType);
            return;
        }

        String action = getParam(msg, isPost, "action");
        if ("deny".equals(action)) {
            redirectWithParams(
                    msg,
                    redirectUri,
                    Map.of(
                            "error", "access_denied",
                            "error_description", "The user denied the authorization request"),
                    state);
            return;
        }

        if (!isPost) {
            setLoginResponse(
                    msg,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    codeChallenge,
                    codeChallengeMethod,
                    null);
            return;
        }

        String username = DevUtils.getFormParam(msg, "username");
        String password = DevUtils.getFormParam(msg, "password");
        if (!isValid(username, password)) {
            setLoginResponse(
                    msg,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    codeChallenge,
                    codeChallengeMethod,
                    "Invalid username or password");
            return;
        }

        String code = RandomStringUtils.secure().nextAlphanumeric(32);
        authorizationCodes.put(
                code,
                new AuthCode(
                        clientId,
                        redirectUri,
                        codeChallenge,
                        codeChallengeMethod,
                        scope,
                        username,
                        System.currentTimeMillis() + AUTH_CODE_TTL_MILLIS));
        redirectWithParams(msg, redirectUri, Map.of("code", code), state);
    }

    private void handleToken(HttpMessage msg) throws Exception {
        String grantType = DevUtils.getFormParam(msg, "grant_type");
        String[] clientCredentials = extractClientCredentials(msg);
        String clientId = clientCredentials[0];
        String clientSecret = clientCredentials[1];

        JSONObject response;
        if ("authorization_code".equals(grantType)) {
            response = handleAuthorizationCodeGrant(msg, clientId, clientSecret);
        } else if ("client_credentials".equals(grantType)) {
            response = handleClientCredentialsGrant(clientId, clientSecret);
        } else if ("password".equals(grantType)) {
            response = handlePasswordGrant(msg, clientId, clientSecret);
        } else if ("refresh_token".equals(grantType)) {
            response = handleRefreshTokenGrant(msg, clientId, clientSecret);
        } else {
            response = errorJson("unsupported_grant_type", "Unsupported grant_type: " + grantType);
        }

        boolean isError = response.has("error");
        if (!isError && isCustomFieldStyle(msg)) {
            renameField(response, "access_token", "accessToken");
            renameField(response, "refresh_token", "refreshToken");
        }
        getServer()
                .setJsonResponse(
                        isError ? STATUS_BAD_REQUEST : TestProxyServer.STATUS_OK, response, msg);
        msg.getResponseHeader().setHeader("Access-Control-Allow-Origin", "*");
    }

    private JSONObject handleAuthorizationCodeGrant(
            HttpMessage msg, String clientId, String clientSecret) throws Exception {
        String code = DevUtils.getFormParam(msg, "code");
        AuthCode data = code == null ? null : authorizationCodes.remove(code);
        if (data == null || System.currentTimeMillis() > data.expiryMillis) {
            return errorJson("invalid_grant", "Unknown, expired, or already used code");
        }
        if (!isValidClient(clientId, clientSecret)) {
            return errorJson("invalid_client", "Client authentication failed");
        }
        if (StringUtils.isNotEmpty(clientId) && !clientId.equals(data.clientId)) {
            return errorJson("invalid_grant", "client_id does not match the original request");
        }
        String redirectUri = DevUtils.getFormParam(msg, "redirect_uri");
        if (StringUtils.isNotEmpty(redirectUri) && !redirectUri.equals(data.redirectUri)) {
            return errorJson("invalid_grant", "redirect_uri does not match the original request");
        }
        if (StringUtils.isNotEmpty(data.codeChallenge)) {
            String verifier = DevUtils.getFormParam(msg, "code_verifier");
            if (verifier == null
                    || !matchesCodeChallenge(
                            verifier, data.codeChallenge, data.codeChallengeMethod)) {
                return errorJson("invalid_grant", "PKCE code_verifier validation failed");
            }
        }
        return issueTokens(data.username, data.scope, true);
    }

    private JSONObject handleClientCredentialsGrant(String clientId, String clientSecret) {
        if (!isValidClient(clientId, clientSecret)) {
            return errorJson("invalid_client", "Client authentication failed");
        }
        return issueTokens(clientId, null, false);
    }

    private JSONObject handlePasswordGrant(HttpMessage msg, String clientId, String clientSecret) {
        if (!isValidClient(clientId, clientSecret)) {
            return errorJson("invalid_client", "Client authentication failed");
        }
        String username = DevUtils.getFormParam(msg, "username");
        String password = DevUtils.getFormParam(msg, "password");
        if (!isValid(username, password)) {
            return errorJson("invalid_grant", "Invalid username or password");
        }
        return issueTokens(username, DevUtils.getFormParam(msg, "scope"), true);
    }

    private JSONObject handleRefreshTokenGrant(
            HttpMessage msg, String clientId, String clientSecret) {
        if (!isValidClient(clientId, clientSecret)) {
            return errorJson("invalid_client", "Client authentication failed");
        }
        String refreshToken = DevUtils.getFormParam(msg, "refresh_token");
        String username = refreshToken == null ? null : refreshTokenToUser.get(refreshToken);
        if (username == null) {
            return errorJson("invalid_grant", "Unknown refresh token");
        }
        JSONObject response = issueTokens(username, DevUtils.getFormParam(msg, "scope"), false);
        response.put("refresh_token", refreshToken);
        return response;
    }

    private void handleUserInfo(HttpMessage msg) throws Exception {
        if (HttpRequestHeader.OPTIONS.equals(msg.getRequestHeader().getMethod())) {
            msg.setResponseBody("");
            msg.setResponseHeader(TestProxyServer.getDefaultResponseHeader("text/plain", 0));
            msg.getResponseHeader().setHeader("Access-Control-Allow-Origin", "*");
            msg.getResponseHeader()
                    .setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
            msg.getResponseHeader().setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            return;
        }
        if (!HttpRequestHeader.GET.equals(msg.getRequestHeader().getMethod())
                || !"userinfo".equals(getPageName(msg))) {
            return;
        }
        String authHeader = msg.getRequestHeader().getHeader("Authorization");
        String token =
                authHeader != null && authHeader.startsWith("Bearer ")
                        ? authHeader.substring("Bearer ".length())
                        : authHeader;
        String username = token == null ? null : getUser(token);

        JSONObject response = new JSONObject();
        if (username == null) {
            response.put("error", "invalid_token");
            getServer().setJsonResponse(STATUS_UNAUTHORIZED, response, msg);
        } else {
            response.put("sub", username);
            response.put("username", username);
            getServer().setJsonResponse(response, msg);
        }
        msg.getResponseHeader().setHeader("Access-Control-Allow-Origin", "*");
    }

    private JSONObject issueTokens(String subject, String scope, boolean includeRefreshToken) {
        JSONObject response = new JSONObject();
        response.put("access_token", getToken(subject));
        response.put("token_type", "Bearer");
        response.put("expires_in", 3600);
        if (StringUtils.isNotEmpty(scope)) {
            response.put("scope", scope);
        }
        if (includeRefreshToken) {
            String refreshToken = RandomStringUtils.secure().nextAlphanumeric(32);
            refreshTokenToUser.put(refreshToken, subject);
            response.put("refresh_token", refreshToken);
        }
        return response;
    }

    private static JSONObject errorJson(String error, String description) {
        JSONObject json = new JSONObject();
        json.put("error", error);
        json.put("error_description", description);
        return json;
    }

    static void renameField(JSONObject json, String oldKey, String newKey) {
        if (json.has(oldKey)) {
            Object value = json.get(oldKey);
            json.remove(oldKey);
            json.put(newKey, value);
        }
    }

    private static boolean isCustomFieldStyle(HttpMessage msg) {
        return "custom".equals(DevUtils.getFormParam(msg, "field_style"));
    }

    static boolean isValidClient(String clientId, String clientSecret) {
        if (CONFIDENTIAL_CLIENT_ID.equals(clientId)) {
            return CONFIDENTIAL_CLIENT_SECRET.equals(clientSecret);
        }
        if (PUBLIC_CLIENT_ID.equals(clientId)) {
            return StringUtils.isEmpty(clientSecret);
        }
        return false;
    }

    static String[] extractClientCredentials(HttpMessage msg) {
        String authHeader = msg.getRequestHeader().getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            try {
                String decoded =
                        new String(
                                Base64.getDecoder().decode(authHeader.substring("Basic ".length())),
                                StandardCharsets.UTF_8);
                int idx = decoded.indexOf(':');
                if (idx >= 0) {
                    return new String[] {decoded.substring(0, idx), decoded.substring(idx + 1)};
                }
            } catch (IllegalArgumentException e) {
                // Ignore, fall through to body params
            }
        }
        return new String[] {
            DevUtils.getFormParam(msg, "client_id"), DevUtils.getFormParam(msg, "client_secret")
        };
    }

    static boolean matchesCodeChallenge(
            String verifier, String codeChallenge, String codeChallengeMethod) {
        if ("plain".equalsIgnoreCase(codeChallengeMethod)) {
            return verifier.equals(codeChallenge);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            return computed.equals(codeChallenge);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    private static String getParam(HttpMessage msg, boolean isPost, String name) throws Exception {
        return isPost ? DevUtils.getFormParam(msg, name) : DevUtils.getUrlParam(msg, name);
    }

    private void redirectWithParams(
            HttpMessage msg, String redirectUri, Map<String, String> params, String state)
            throws Exception {
        StringBuilder url = new StringBuilder(redirectUri);
        url.append(redirectUri.contains("?") ? "&" : "?");
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                url.append('&');
            }
            first = false;
            url.append(entry.getKey())
                    .append('=')
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        if (StringUtils.isNotEmpty(state)) {
            url.append('&')
                    .append("state=")
                    .append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        }
        DevUtils.setRedirect(msg, url.toString());
    }

    private void setLoginResponse(
            HttpMessage msg,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String error)
            throws Exception {
        String body = getServer().getTextFile(this, "login.html");
        body = body.replace("<!-- CLIENT_ID -->", escapeHtml(clientId));
        body = body.replace("<!-- REDIRECT_URI -->", escapeHtml(redirectUri));
        body = body.replace("<!-- SCOPE -->", escapeHtml(StringUtils.defaultString(scope)));
        body = body.replace("<!-- STATE -->", escapeHtml(StringUtils.defaultString(state)));
        body =
                body.replace(
                        "<!-- CODE_CHALLENGE -->",
                        escapeHtml(StringUtils.defaultString(codeChallenge)));
        body =
                body.replace(
                        "<!-- CODE_CHALLENGE_METHOD -->",
                        escapeHtml(StringUtils.defaultString(codeChallengeMethod)));
        body =
                body.replace(
                        "<!-- ERROR -->",
                        error == null
                                ? ""
                                : "<p style=\"color:red;\">" + escapeHtml(error) + "</p>");
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8, msg.getResponseBody().length()));
    }

    private void setErrorResponse(HttpMessage msg, String error) throws Exception {
        String body = getServer().getTextFile(this, "error.html");
        body = body.replace("<!-- ERROR -->", escapeHtml(error));
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8, msg.getResponseBody().length()));
    }

    private void setHtmlResponse(HttpMessage msg, String fileName) throws Exception {
        String body = getServer().getTextFile(this, fileName);
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8, msg.getResponseBody().length()));
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;")
                .replace("\"", "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private static class AuthCode {
        private final String clientId;
        private final String redirectUri;
        private final String codeChallenge;
        private final String codeChallengeMethod;
        private final String scope;
        private final String username;
        private final long expiryMillis;

        AuthCode(
                String clientId,
                String redirectUri,
                String codeChallenge,
                String codeChallengeMethod,
                String scope,
                String username,
                long expiryMillis) {
            this.clientId = clientId;
            this.redirectUri = redirectUri;
            this.codeChallenge = codeChallenge;
            this.codeChallengeMethod = codeChallengeMethod;
            this.scope = scope;
            this.username = username;
            this.expiryMillis = expiryMillis;
        }
    }
}
