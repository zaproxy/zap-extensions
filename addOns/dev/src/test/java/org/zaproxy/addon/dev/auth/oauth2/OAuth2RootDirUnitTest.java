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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Unit tests for the pure-logic helpers in {@link OAuth2RootDir} - the parts that don't require a
 * running {@link org.zaproxy.addon.dev.TestProxyServer}/domain-listener plumbing to exercise.
 */
class OAuth2RootDirUnitTest {

    @Test
    void shouldValidateConfidentialClient() {
        assertThat(OAuth2RootDir.isValidClient("test-client", "test-secret"), is(equalTo(true)));
    }

    @Test
    void shouldRejectConfidentialClientWithWrongSecret() {
        assertThat(OAuth2RootDir.isValidClient("test-client", "wrong-secret"), is(equalTo(false)));
    }

    @Test
    void shouldRejectConfidentialClientWithNoSecret() {
        assertThat(OAuth2RootDir.isValidClient("test-client", null), is(equalTo(false)));
    }

    @Test
    void shouldValidatePublicClientWithNoSecret() {
        assertThat(OAuth2RootDir.isValidClient("test-public-client", null), is(equalTo(true)));
        assertThat(OAuth2RootDir.isValidClient("test-public-client", ""), is(equalTo(true)));
    }

    @Test
    void shouldRejectPublicClientIfASecretIsPresented() {
        assertThat(
                OAuth2RootDir.isValidClient("test-public-client", "some-secret"),
                is(equalTo(false)));
    }

    @Test
    void shouldRejectUnknownClient() {
        assertThat(OAuth2RootDir.isValidClient("unknown-client", "anything"), is(equalTo(false)));
        assertThat(OAuth2RootDir.isValidClient(null, null), is(equalTo(false)));
    }

    @Test
    void shouldExtractClientCredentialsFromBasicAuthHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                new HttpRequestHeader(
                        "POST /token HTTP/1.1\r\nHost: authserver.oauth2.zap\r\n\r\n"));
        String basic =
                Base64.getEncoder()
                        .encodeToString("test-client:test-secret".getBytes(StandardCharsets.UTF_8));
        msg.getRequestHeader().setHeader("Authorization", "Basic " + basic);

        // When
        String[] creds = OAuth2RootDir.extractClientCredentials(msg);

        // Then
        assertThat(creds[0], is(equalTo("test-client")));
        assertThat(creds[1], is(equalTo("test-secret")));
    }

    @Test
    void shouldExtractClientCredentialsFromFormParamsWhenNoAuthHeader() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                new HttpRequestHeader(
                        "POST /token HTTP/1.1\r\nHost: authserver.oauth2.zap\r\n\r\n"));
        msg.getRequestHeader()
                .setHeader(
                        org.parosproxy.paros.network.HttpHeader.CONTENT_TYPE,
                        "application/x-www-form-urlencoded");
        msg.getRequestBody()
                .setBody(
                        "grant_type=client_credentials&client_id=test-client&client_secret=test-secret");

        // When
        String[] creds = OAuth2RootDir.extractClientCredentials(msg);

        // Then
        assertThat(creds[0], is(equalTo("test-client")));
        assertThat(creds[1], is(equalTo("test-secret")));
    }

    @Test
    void shouldMatchS256CodeChallengeUsingRfc7636TestVector() throws Exception {
        // Given - the exact example verifier/challenge pair from RFC 7636 Appendix B
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        // When / Then
        assertThat(
                OAuth2RootDir.matchesCodeChallenge(verifier, challenge, "S256"), is(equalTo(true)));
        assertThat(
                OAuth2RootDir.matchesCodeChallenge(verifier + "x", challenge, "S256"),
                is(equalTo(false)));

        // And it matches independent manual computation
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
        String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        assertThat(challenge, is(equalTo(expected)));
    }

    @Test
    void shouldMatchPlainCodeChallenge() {
        assertThat(
                OAuth2RootDir.matchesCodeChallenge("my-verifier", "my-verifier", "plain"),
                is(equalTo(true)));
        assertThat(
                OAuth2RootDir.matchesCodeChallenge("my-verifier", "other-value", "plain"),
                is(equalTo(false)));
    }

    @Test
    void shouldRenameFieldWhenPresent() {
        // Given
        JSONObject json = new JSONObject();
        json.put("access_token", "abc123");
        json.put("token_type", "Bearer");

        // When
        OAuth2RootDir.renameField(json, "access_token", "accessToken");

        // Then
        assertThat(json.has("access_token"), is(equalTo(false)));
        assertThat(json.getString("accessToken"), is(equalTo("abc123")));
        assertThat(json.getString("token_type"), is(equalTo("Bearer")));
    }

    @Test
    void shouldNotFailRenamingAnAbsentField() {
        // Given
        JSONObject json = new JSONObject();
        json.put("token_type", "Bearer");

        // When
        OAuth2RootDir.renameField(json, "access_token", "accessToken");

        // Then
        assertThat(json.has("accessToken"), is(equalTo(false)));
        assertThat(json.getString("token_type"), is(equalTo("Bearer")));
    }
}
