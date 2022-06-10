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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.client.KeyStoreEntry.Type;

/** Unit test for {@link KeyStoreEntry}. */
class KeyStoreEntryUnitTest {

    private Type type;
    private String name;
    private KeyStore keyStore;
    private String password;

    private String alias1;
    private Certificate certificate1;
    private String alias3;
    private Certificate certificate3;
    private KeyStoreEntry keyStoreEntry;

    @BeforeEach
    void setUp() throws Exception {
        type = Type.PKCS11;
        name = "Name";
        password = "password";
        keyStore = mock(KeyStore.class);
        alias1 = "Alias 1";
        alias3 = "Alias 3";
        given(keyStore.aliases())
                .willReturn(Collections.enumeration(Arrays.asList(alias1, "Alias 2", alias3)));
        certificate1 = mock(Certificate.class);
        given(keyStore.isKeyEntry(alias1)).willReturn(true);
        given(keyStore.getCertificate(alias1)).willReturn(certificate1);
        certificate3 = mock(Certificate.class);
        given(keyStore.isKeyEntry(alias3)).willReturn(true);
        given(keyStore.getCertificate(alias3)).willReturn(certificate3);
        keyStoreEntry = new KeyStoreEntry(type, name, keyStore, password);
    }

    @Test
    void shouldThrowExceptionWhenCreatingKeyStoreEntryWithNullType() {
        // Given
        type = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new KeyStoreEntry(type, name, keyStore, password));
    }

    @Test
    void shouldThrowExceptionWhenCreatingKeyStoreEntryWithNullName() {
        // Given
        name = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new KeyStoreEntry(type, name, keyStore, password));
    }

    @Test
    void shouldThrowExceptionWhenCreatingKeyStoreEntryWithNullKeyStore() {
        // Given
        keyStore = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new KeyStoreEntry(type, name, keyStore, password));
    }

    @ParameterizedTest
    @CsvSource({"PKCS11,PKCS#11: Name", "PKCS12,PKCS#12: Name"})
    void shouldGetNameWithKeyStoreType(Type type, String expectedName) throws Exception {
        // Given / When
        keyStoreEntry = new KeyStoreEntry(type, name, keyStore, password);
        // Then
        assertThat(keyStoreEntry.getName(), is(equalTo(expectedName)));
    }

    @Test
    void shouldGetKeyStore() {
        assertThat(keyStoreEntry.getKeyStore(), is(sameInstance(keyStore)));
    }

    @ParameterizedTest
    @EnumSource(Type.class)
    void shouldGetType(Type type) throws Exception {
        // Given / When
        keyStoreEntry = new KeyStoreEntry(type, name, keyStore, password);
        // Then
        assertThat(keyStoreEntry.getType(), is(equalTo(type)));
    }

    @Test
    void shouldThrowExceptionOccurredWhileReadingCertificates() throws Exception {
        // Given
        given(keyStore.aliases()).willThrow(KeyStoreException.class);
        // When / Then
        assertThrows(
                KeyStoresException.class, () -> new KeyStoreEntry(type, name, keyStore, password));
    }

    @Test
    void shouldHaveNoCertificatesIfNoneInKeyStore() throws Exception {
        // Given
        given(keyStore.aliases()).willReturn(Collections.emptyEnumeration());
        keyStoreEntry = new KeyStoreEntry(type, name, keyStore, password);
        // When
        List<CertificateEntry> certificateEntries = keyStoreEntry.getCertificates();
        // Then
        assertThat(certificateEntries, is(notNullValue()));
        assertThat(certificateEntries, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldGetCertificateEntry(int index) {
        // Given / When
        CertificateEntry certificateEntry = keyStoreEntry.getCertificate(index);
        // Then
        assertThat(certificateEntry, is(notNullValue()));
    }

    @Test
    void shouldHaveSelfAsCertificateEntryParent() {
        // Given / When
        CertificateEntry certificateEntry = keyStoreEntry.getCertificate(0);
        // Then
        assertThat(certificateEntry, is(notNullValue()));
        assertThat(certificateEntry.getParent(), is(sameInstance(keyStoreEntry)));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1})
    void shouldHaveCorrectIndexInCertificateEntry(int index) {
        // Given / When
        CertificateEntry certificateEntry = keyStoreEntry.getCertificate(index);
        // Then
        assertThat(certificateEntry, is(notNullValue()));
        assertThat(certificateEntry.getIndex(), is(equalTo(index)));
    }

    @Test
    void shouldHaveCorrectCertificateInCertificateEntry() {
        // Given / When
        CertificateEntry certificateEntry = keyStoreEntry.getCertificate(1);
        // Then
        assertThat(certificateEntry, is(notNullValue()));
        assertThat(certificateEntry.getCertificate(), is(sameInstance(certificate3)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 2})
    void shouldGetNullCertificateForInvalidIndex(int index) {
        // Given / When
        CertificateEntry certificateEntry = keyStoreEntry.getCertificate(index);
        // Then
        assertThat(certificateEntry, is(nullValue()));
    }

    @Test
    void shouldGetCertificates() {
        // Given / When
        List<CertificateEntry> certificateEntries = keyStoreEntry.getCertificates();
        // Then
        assertThat(certificateEntries, is(notNullValue()));
        assertThat(certificateEntries, hasSize(2));
    }

    @Test
    void shouldReturnNameForStringRepresentation() {
        // Given
        String name = keyStoreEntry.getName();
        // When / Then
        assertThat(keyStoreEntry.toString(), is(equalTo(name)));
    }
}
