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
package org.zaproxy.addon.network.internal.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verify;
import static org.mockito.Mockito.mock;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link SingleAliasKeyManager}. */
class SingleAliasKeyManagerUnitTest {

    private KeyStore keyStore;
    private String alias;
    private char[] password;
    private SingleAliasKeyManager singleAliasKeyManager;

    @BeforeEach
    void setUp() {
        keyStore = mock(KeyStore.class);
        alias = "Alias";
        password = new char[] {'a', 'b', 'c'};
        singleAliasKeyManager = new SingleAliasKeyManager(keyStore, alias, password);
    }

    @Test
    void shouldThrowExceptionWhenCreatingSingleAliasKeyManagerWithNullKeyStore() {
        // Given
        keyStore = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SingleAliasKeyManager(keyStore, alias, password));
    }

    @Test
    void shouldThrowExceptionWhenCreatingSingleAliasKeyManagerWithNullAlias() {
        // Given
        alias = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SingleAliasKeyManager(keyStore, alias, password));
    }

    @Test
    void shouldThrowExceptionWhenCreatingSingleAliasKeyManagerWithNullPassword() {
        // Given
        password = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new SingleAliasKeyManager(keyStore, alias, password));
    }

    @Test
    void shouldGetPrivateKey() throws Exception {
        // Given
        PrivateKey privateKey = mock(PrivateKey.class);
        given(keyStore.getKey(alias, password)).willReturn(privateKey);
        // When
        PrivateKey obtainedPrivatekey = singleAliasKeyManager.getPrivateKey(alias);
        // Then
        assertThat(obtainedPrivatekey, is(sameInstance(privateKey)));
        verify(keyStore).getKey(alias, password);
    }

    @Test
    void shouldReturnNullWhenFailedToGetPrivateKey() throws Exception {
        // Given
        given(keyStore.getKey(alias, password)).willThrow(KeyStoreException.class);
        // When
        PrivateKey obtainedPrivatekey = singleAliasKeyManager.getPrivateKey(alias);
        // Then
        assertThat(obtainedPrivatekey, is(nullValue()));
    }

    @Test
    void shouldNotGetPrivateKeyIfNotSameAlias() throws Exception {
        // Given
        given(keyStore.getKey(alias, password)).willReturn(null);
        // When
        PrivateKey obtainedPrivatekey = singleAliasKeyManager.getPrivateKey(alias);
        // Then
        assertThat(obtainedPrivatekey, is(nullValue()));
    }

    @Test
    void shouldChooseClientAlias() {
        // Given / When
        String chosenAlias = singleAliasKeyManager.chooseClientAlias(null, null, null);
        // Then
        assertThat(chosenAlias, is(equalTo(alias)));
    }

    @Test
    void shouldChooseServerAlias() {
        // Given / When
        String chosenAlias = singleAliasKeyManager.chooseServerAlias(null, null, null);
        // Then
        assertThat(chosenAlias, is(equalTo(alias)));
    }

    @Test
    void shouldGetClientAliases() {
        // Given / When
        String[] clientAliases = singleAliasKeyManager.getClientAliases(null, null);
        // Then
        assertThat(clientAliases, is(arrayContaining(alias)));
    }

    @Test
    void shouldGetServerAliases() {
        // Given / When
        String[] serverAliases = singleAliasKeyManager.getServerAliases(null, null);
        // Then
        assertThat(serverAliases, is(arrayContaining(alias)));
    }

    @Test
    void shoudGetCertificateChain() throws Exception {
        // Given
        X509Certificate cert1 = mock(X509Certificate.class);
        X509Certificate cert2 = mock(X509Certificate.class);
        given(keyStore.getCertificateChain(alias)).willReturn(new X509Certificate[] {cert1, cert2});
        // When
        X509Certificate[] obtainedCertificateChain =
                singleAliasKeyManager.getCertificateChain(alias);
        // Then
        assertThat(obtainedCertificateChain, is(arrayContaining(cert1, cert2)));
    }

    @Test
    void shouldReturnNullWhenFailedToGetCertificateChain() throws Exception {
        // Given
        given(keyStore.getCertificateChain(alias)).willThrow(KeyStoreException.class);
        // When
        X509Certificate[] obtainedCertificateChain =
                singleAliasKeyManager.getCertificateChain(alias);
        // Then
        assertThat(obtainedCertificateChain, is(nullValue()));
    }

    @Test
    void shoudNotGetCertificateChainIfNotSameAlias() throws Exception {
        // Given
        X509Certificate cert1 = mock(X509Certificate.class);
        X509Certificate cert2 = mock(X509Certificate.class);
        given(keyStore.getCertificateChain(alias)).willReturn(new X509Certificate[] {cert1, cert2});
        // When
        X509Certificate[] obtainedCertificateChain =
                singleAliasKeyManager.getCertificateChain("Other Alias");
        // Then
        assertThat(obtainedCertificateChain, is(nullValue()));
    }
}
