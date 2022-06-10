/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client.apachev5;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.net.PasswordAuthentication;
import java.util.Locale;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.NTCredentials;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.HttpProxy;

/** Unit test for  {@link ProxyCredentialsProvider}. */
class ProxyCredentialsProviderUnitTest {

    private static final HttpProxy HTTP_PROXY =
            new HttpProxy(
                    "proxy.example.org",
                    443,
                    "Realm",
                    new PasswordAuthentication("UserName", "Password".toCharArray()));

    private ConnectionOptions connectionOptions;
    private ProxyCredentialsProvider proxyCredentialsProvider;

    @BeforeEach
    void setUp() {
        connectionOptions = mock(ConnectionOptions.class);
        given(connectionOptions.getHttpProxy()).willReturn(HTTP_PROXY);
        given(connectionOptions.isHttpProxyEnabled()).willReturn(true);
        given(connectionOptions.isHttpProxyAuthEnabled()).willReturn(true);
        proxyCredentialsProvider = new ProxyCredentialsProvider(connectionOptions);
    }

    @ParameterizedTest
    @ValueSource(strings = {"basic", "Basic", "digest", "Digest"})
    void shouldProvideUsernamePasswordCredentialsForBasicAndDigestSchemes(String scheme) {
        // Given
        AuthScope authScope = createProxyAuthScope(scheme);
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(instanceOf(UsernamePasswordCredentials.class)));
        UsernamePasswordCredentials credentials = (UsernamePasswordCredentials) providedCredentials;
        assertThat(
                credentials.getUserName(),
                is(equalTo(HTTP_PROXY.getPasswordAuthentication().getUserName())));
        assertThat(
                credentials.getPassword(),
                is(equalTo(HTTP_PROXY.getPasswordAuthentication().getPassword())));
    }

    @Test
    void shouldProvideNtCredentialsForOtherSchemes() {
        // Given
        AuthScope authScope = createProxyAuthScope("ntlm");
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(instanceOf(NTCredentials.class)));
        NTCredentials credentials = (NTCredentials) providedCredentials;
        assertThat(
                credentials.getUserName(),
                is(equalTo(HTTP_PROXY.getPasswordAuthentication().getUserName())));
        assertThat(
                credentials.getPassword(),
                is(equalTo(HTTP_PROXY.getPasswordAuthentication().getPassword())));
        assertThat(credentials.getWorkstation(), is(equalTo("")));
        assertThat(
                credentials.getDomain(),
                is(equalTo(HTTP_PROXY.getRealm().toUpperCase(Locale.ROOT))));
    }

    @Test
    void shouldNotProvideCredentialsIfProxyNotEnabled() {
        // Given
        AuthScope authScope = createProxyAuthScope("basic");
        given(connectionOptions.isHttpProxyEnabled()).willReturn(false);
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(nullValue()));
    }

    @Test
    void shouldNotProvideCredentialsIfProxyAuthNotEnabled() {
        // Given
        AuthScope authScope = createProxyAuthScope("basic");
        given(connectionOptions.isHttpProxyAuthEnabled()).willReturn(false);
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(nullValue()));
    }

    @Test
    void shouldNotProvideCredentialsIfHostDoesNotMatch() {
        // Given
        AuthScope authScope =
                createAuthScope("basic", "Other Host", HTTP_PROXY.getPort(), HTTP_PROXY.getRealm());
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(nullValue()));
    }

    @Test
    void shouldNotProvideCredentialsIfPortDoesNotMatch() {
        // Given
        AuthScope authScope =
                createAuthScope(
                        "basic",
                        HTTP_PROXY.getHost(),
                        HTTP_PROXY.getPort() + 1,
                        HTTP_PROXY.getRealm());
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(nullValue()));
    }

    @Test
    void shouldNotProvideCredentialsIfRealmDoesNotMatch() {
        // Given
        AuthScope authScope =
                createAuthScope("basic", HTTP_PROXY.getHost(), HTTP_PROXY.getPort(), "Other Realm");
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(nullValue()));
    }

    @Test
    void shouldProvideCredentialsIfAnyRealmMatch() {
        // Given
        HttpProxy httpProxy =
                new HttpProxy(
                        "proxy.example.org",
                        443,
                        "",
                        new PasswordAuthentication("UserName", "Password".toCharArray()));
        given(connectionOptions.getHttpProxy()).willReturn(httpProxy);
        AuthScope authScope =
                createAuthScope(
                        "basic",
                        httpProxy.getHost(),
                        httpProxy.getPort(),
                        "Other Realm But Any Allowed");
        // When
        Credentials providedCredentials = proxyCredentialsProvider.getCredentials(authScope, null);
        // Then
        assertThat(providedCredentials, is(notNullValue()));
    }

    private static AuthScope createProxyAuthScope(String scheme) {
        return createAuthScope(
                scheme, HTTP_PROXY.getHost(), HTTP_PROXY.getPort(), HTTP_PROXY.getRealm());
    }

    private static AuthScope createAuthScope(String scheme, String host, int port, String realm) {
        return new AuthScope(null, host, port, realm, scheme);
    }
}
