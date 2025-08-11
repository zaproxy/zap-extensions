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
package org.zaproxy.addon.network;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

public class NetworkUtilsUnitTest {

    @ParameterizedTest
    @CsvSource({
        "Basic, true",
        "basiC, true",
        "digest, false",
        ", false",
    })
    void shouldIdBasicAuth(String header, String result) throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://www.example.com/basic/", true));
        msg.getResponseHeader().setHeader(HttpHeader.WWW_AUTHENTICATE, header);

        // When
        boolean basic = NetworkUtils.isHttpBasicAuth(msg);

        // Then
        assertThat(basic, is(equalTo(Boolean.parseBoolean(result))));
    }

    @ParameterizedTest
    @CsvSource({
        "Digest, true",
        "diGEST, true",
        "basic, false",
        ", false",
    })
    void shouldIdDigestAuth(String header, String result) throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://www.example.com/basic/", true));
        msg.getResponseHeader().setHeader(HttpHeader.WWW_AUTHENTICATE, header);

        // When
        boolean basic = NetworkUtils.isHttpDigestAuth(msg);

        // Then
        assertThat(basic, is(equalTo(Boolean.parseBoolean(result))));
    }

    @Test
    void shouldGenerateBasicAuth() throws Exception {
        // Given
        UsernamePasswordAuthenticationCredentials creds =
                new UsernamePasswordAuthenticationCredentials("username", "password");

        // When
        String auth = NetworkUtils.getHttpBasicAuthorization(creds);

        // Then
        assertThat(auth, is(equalTo("Basic dXNlcm5hbWU6cGFzc3dvcmQ=")));
    }

    @Test
    void shouldGenerateDigestAuth() throws Exception {
        HttpMessage msg = new HttpMessage(new URI("https://www.example.com/digest/", true));
        msg.getResponseHeader()
                .setHeader(
                        HttpHeader.WWW_AUTHENTICATE,
                        "Digest realm=\"test\", domain=\"/HTTP/Digest\", nonce=\"e561a741e25a463317199abe129bb096\"");
        UsernamePasswordAuthenticationCredentials creds =
                new UsernamePasswordAuthenticationCredentials("username", "password");

        // When
        String auth = NetworkUtils.getHttpDigestAuthorization(msg, creds);

        // Then
        assertThat(
                auth,
                is(
                        equalTo(
                                "Digest username=\"username\", realm=\"test\", nonce=\"e561a741e25a463317199abe129bb096\", uri=\"/digest/\", response=\"d7aaee78d91c0e29bca8a57fa26f1ea9\", algorithm=MD5")));
    }

    @Test
    void shouldHandleNoHeaderDigestAuth() throws Exception {
        HttpMessage msg = new HttpMessage(new URI("https://www.example.com/digest/", true));
        UsernamePasswordAuthenticationCredentials creds =
                new UsernamePasswordAuthenticationCredentials("username", "password");

        // When
        String auth = NetworkUtils.getHttpDigestAuthorization(msg, creds);

        // Then
        assertThat(auth, is(nullValue()));
    }
}
