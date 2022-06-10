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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit test for {@link CertificateEntry}. */
class CertificateEntryUnitTest {

    private String alias;
    private int index;
    private String password;
    private PrivateKey privateKey;
    private KeyStore keyStore;
    private KeyStoreEntry parent;
    private Certificate certificate;

    private CertificateEntry certificateEntry;

    @BeforeEach
    void setUp() throws Exception {
        alias = "Alias";
        index = 1234;
        password = "password";
        privateKey = mock(PrivateKey.class);
        keyStore = mock(KeyStore.class);
        given(keyStore.getKey(alias, password.toCharArray())).willReturn(privateKey);
        parent = mock(KeyStoreEntry.class);
        given(parent.getKeyStore()).willReturn(keyStore);
        certificate = mock(Certificate.class);
        certificateEntry = new CertificateEntry(parent, certificate, alias, index);
    }

    @Test
    void shouldThrowExceptionWhenCreatingCertificateEntryWithNullParent() {
        // Given
        parent = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CertificateEntry(parent, certificate, alias, index));
    }

    @Test
    void shouldThrowExceptionWhenCreatingCertificateEntryWithNullCertificate() {
        // Given
        certificate = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CertificateEntry(parent, certificate, alias, index));
    }

    @Test
    void shouldThrowExceptionWhenCreatingCertificateEntryWithNullAlias() {
        // Given
        alias = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CertificateEntry(parent, certificate, alias, index));
    }

    @Test
    void shouldGetParent() {
        assertThat(certificateEntry.getParent(), is(equalTo(parent)));
    }

    @Test
    void shouldGetCertificate() {
        assertThat(certificateEntry.getCertificate(), is(equalTo(certificate)));
    }

    @Test
    void shouldGetIndex() {
        assertThat(certificateEntry.getIndex(), is(equalTo(index)));
    }

    @Test
    void shouldExtractNameFromCertificate() {
        // Given
        given(certificate.toString())
                .willReturn(
                        "C=EX, ST=Example, O=Example, CN=Abc 123\n  Signature Algorithm: SHA256withRSA");
        // When
        certificateEntry = new CertificateEntry(parent, certificate, alias, index);
        // Then
        assertThat(
                certificateEntry.getName(),
                is(equalTo("Abc 123\n  Signature Algorithm: SHA256withRSA [Alias]")));
    }

    @Test
    void shouldUseOnlyAliasIfUnableToExtractNameExtractNameFromCertificate() {
        // Given
        given(certificate.toString()).willReturn("No CN");
        // When
        certificateEntry = new CertificateEntry(parent, certificate, alias, index);
        // Then
        assertThat(certificateEntry.getName(), is(equalTo("Alias")));
    }

    @Test
    void shouldUnlockCertificate() {
        // Given / When
        boolean unlocked = certificateEntry.unlock(password);
        // Then
        assertThat(unlocked, is(equalTo(true)));
        assertThat(certificateEntry.isUnlocked(), is(equalTo(true)));
        assertThat(certificateEntry.getSocketFactory(), is(notNullValue()));
    }

    @Test
    void shouldNotUnlockCertificateIfNoPrivateKey() throws Exception {
        // Given
        given(keyStore.getKey(alias, password.toCharArray())).willReturn(null);
        // When
        boolean unlocked = certificateEntry.unlock(password);
        // Then
        assertThat(unlocked, is(equalTo(false)));
        assertThat(certificateEntry.isUnlocked(), is(equalTo(false)));
        assertThat(certificateEntry.getSocketFactory(), is(nullValue()));
    }

    @Test
    void shouldInvalidateSessions() throws Exception {
        // Given
        boolean unlocked = certificateEntry.unlock(password);
        // When / Then
        assertDoesNotThrow(() -> certificateEntry.invalidateSession());
        assertThat(unlocked, is(equalTo(true)));
    }

    @Test
    void shouldDoNothingIfNotUnlockedOnInvalidateSessions() throws Exception {
        assertDoesNotThrow(() -> certificateEntry.invalidateSession());
    }

    @Test
    void shouldReturnNameForStringRepresentation() throws Exception {
        // Given
        String name = certificateEntry.getName();
        // When / Then
        assertThat(certificateEntry.toString(), is(equalTo(name)));
    }
}
