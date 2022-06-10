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
package org.zaproxy.addon.network;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.client.CertificateEntry;
import org.zaproxy.addon.network.internal.client.KeyStoreEntry;
import org.zaproxy.addon.network.internal.client.KeyStores;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ClientCertificatesOptions}. */
class ClientCertificatesOptionsUnitTest {

    private static final String USE_CERTIFICATE = "network.clientCertificates.use";
    private static final String PKCS12_FILE_KEY = "network.clientCertificates.pkcs12.file";
    private static final String PKCS12_PASSWORD_KEY = "network.clientCertificates.pkcs12.password";
    private static final String PKCS12_INDEX_KEY = "network.clientCertificates.pkcs12.index";
    private static final String PKCS12_STORE_KEY = "network.clientCertificates.pkcs12.store";
    private static final String PKCS11_USE_SLI_KEY = "network.clientCertificates.pkcs11.useSli";

    private KeyStores keyStores;
    private ZapXmlConfiguration config;
    private ClientCertificatesOptions options;

    @BeforeEach
    void setUp() {
        keyStores = mock(KeyStores.class);

        options = new ClientCertificatesOptions(keyStores);
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(
                options.getConfigVersionKey(), is(equalTo("network.clientCertificates[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        // Given
        options = new ClientCertificatesOptions();
        // When / Then
        assertDefaultValues();
    }

    private void assertDefaultValues() {
        assertThat(options.isUseCertificate(), is(equalTo(false)));
        assertThat(options.getPkcs12File(), is(equalTo("")));
        assertThat(options.getPkcs12Password(), is(equalTo("")));
        assertThat(options.getPkcs12Index(), is(equalTo(0)));
        assertThat(options.isPkcs12Store(), is(equalTo(false)));
        assertThat(options.isPkcs11UseSlotListIndex(), is(equalTo(false)));
        assertThat(options.getKeyStores(), is(notNullValue()));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertDefaultValues();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithUseCertificate(boolean use) {
        // Given
        config.setProperty(USE_CERTIFICATE, use);
        // When
        options.load(config);
        // Then
        assertThat(options.isUseCertificate(), is(equalTo(use)));
    }

    @Test
    void shouldUseDefaultWithInvalidUseCertificate() {
        // Given
        config.setProperty(USE_CERTIFICATE, "not a boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isUseCertificate(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistUseCertificate(boolean use) throws Exception {
        // Given / When
        options.setUseCertificate(use);
        // Then
        assertThat(options.isUseCertificate(), is(equalTo(use)));
        assertThat(config.getBoolean(USE_CERTIFICATE), is(equalTo(use)));
    }

    @Test
    void shouldLoadConfigWithPkcs12File() {
        // Given
        String file = "/path/to/file";
        config.setProperty(PKCS12_FILE_KEY, file);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12File(), is(equalTo(file)));
    }

    @Test
    void shouldUseDefaultWithNoPkcs12File() {
        // Given
        config.setProperty(PKCS12_FILE_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12File(), is(equalTo("")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "/path/to/file"})
    void shouldSetPkcs12File(String file) throws Exception {
        // Given / When
        options.setPkcs12File(file);
        // Then
        assertThat(options.getPkcs12File(), is(equalTo(file)));
        assertThat(config.getString(PKCS12_FILE_KEY), is(equalTo(null)));
    }

    @Test
    void shouldThrowIfSettingNullPkcs12File() throws Exception {
        // Given
        String file = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setPkcs12File(file));
    }

    @Test
    void shouldLoadConfigWithPkcs12Password() {
        // Given
        String password = "password";
        config.setProperty(PKCS12_PASSWORD_KEY, password);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12Password(), is(equalTo(password)));
    }

    @Test
    void shouldUseDefaultWithNoPkcs12Password() {
        // Given
        config.setProperty(PKCS12_PASSWORD_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12Password(), is(equalTo("")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "password"})
    void shouldSetPkcs12Password(String password) throws Exception {
        // Given / When
        options.setPkcs12Password(password);
        // Then
        assertThat(options.getPkcs12Password(), is(equalTo(password)));
        assertThat(config.getString(PKCS12_PASSWORD_KEY), is(equalTo(null)));
    }

    @Test
    void shouldThrowIfSettingNullPkcs12Password() throws Exception {
        // Given
        String password = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setPkcs12Password(password));
    }

    @Test
    void shouldLoadConfigWithPkcs12Index() {
        // Given
        int index = 1234;
        config.setProperty(PKCS12_INDEX_KEY, index);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12Index(), is(equalTo(index)));
    }

    @Test
    void shouldUseDefaultWithNoPkcs12Index() {
        // Given
        config.setProperty(PKCS12_INDEX_KEY, null);
        // When
        options.load(config);
        // Then
        assertThat(options.getPkcs12Index(), is(equalTo(0)));
    }

    @ParameterizedTest
    @CsvSource({"-1, 0", "0, 0", "1, 1"})
    void shouldSetPkcs12Index(int value, int expected) throws Exception {
        // Given / When
        options.setPkcs12Index(value);
        // Then
        assertThat(options.getPkcs12Index(), is(equalTo(expected)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithPkcs12Store(boolean use) {
        // Given
        config.setProperty(PKCS12_STORE_KEY, use);
        // When
        options.load(config);
        // Then
        assertThat(options.isPkcs12Store(), is(equalTo(use)));
    }

    @Test
    void shouldUseDefaultWithInvalidPkcs12Store() {
        // Given
        config.setProperty(PKCS12_STORE_KEY, "not a boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isPkcs12Store(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistPkcs12Store(boolean use) throws Exception {
        // Given / When
        options.setPkcs12Store(use);
        // Then
        assertThat(options.isPkcs12Store(), is(equalTo(use)));
        assertThat(config.getBoolean(PKCS12_STORE_KEY), is(equalTo(use)));
    }

    @Test
    void shouldPersistPkcs12PropertiesOnStore() throws Exception {
        // Given
        String file = "/path/to/file";
        options.setPkcs12File(file);
        String password = "password";
        options.setPkcs12Password(password);
        int index = 1234;
        options.setPkcs12Index(index);
        // When
        options.setPkcs12Store(true);
        // Then
        assertThat(config.getString(PKCS12_FILE_KEY), is(equalTo(file)));
        assertThat(config.getString(PKCS12_PASSWORD_KEY), is(equalTo(password)));
        assertThat(config.getInt(PKCS12_INDEX_KEY), is(equalTo(index)));
    }

    @Test
    void shouldClearPkcs12PropertiesIfNotStore() throws Exception {
        // Given
        String file = "/path/to/file";
        options.setPkcs12File(file);
        String password = "password";
        options.setPkcs12Password(password);
        int index = 1234;
        options.setPkcs12Index(index);
        options.setPkcs12Store(true);
        // When
        options.setPkcs12Store(false);
        // Then
        assertThat(config.getString(PKCS12_FILE_KEY), is(equalTo("")));
        assertThat(config.getString(PKCS12_PASSWORD_KEY), is(equalTo("")));
        assertThat(config.getInt(PKCS12_INDEX_KEY), is(equalTo(0)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithPkcs11UseSlotListIndex(boolean use) {
        // Given
        config.setProperty(PKCS11_USE_SLI_KEY, use);
        // When
        options.load(config);
        // Then
        assertThat(options.isPkcs11UseSlotListIndex(), is(equalTo(use)));
    }

    @Test
    void shouldUseDefaultWithInvalidPkcs11UseSlotListIndex() {
        // Given
        config.setProperty(PKCS11_USE_SLI_KEY, "not a boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isPkcs11UseSlotListIndex(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistPkcs11UseSlotListIndex(boolean use) throws Exception {
        // Given / When
        options.setPkcs11UseSlotListIndex(use);
        // Then
        assertThat(options.isPkcs11UseSlotListIndex(), is(equalTo(use)));
        assertThat(config.getBoolean(PKCS11_USE_SLI_KEY), is(equalTo(use)));
    }

    @Test
    void shouldMigrateOptions() {
        // Given
        config =
                configWith(
                        "<certificate>\n"
                                + "  <use>true</use>\n"
                                + "  <pkcs12>\n"
                                + "    <path>/path/to/file</path>\n"
                                + "    <password>password</password>\n"
                                + "    <index>1234</index>\n"
                                + "  </pkcs12>\n"
                                + "  <persist>true</persist>\n"
                                + "  <experimentalSlotListIndex>true</experimentalSlotListIndex>\n"
                                + "</certificate>");
        // When
        options.load(config);
        // Then
        assertThat(options.isUseCertificate(), is(equalTo(true)));
        assertThat(options.getPkcs12File(), is(equalTo("/path/to/file")));
        assertThat(options.getPkcs12Password(), is(equalTo("password")));
        assertThat(options.getPkcs12Index(), is(equalTo(1234)));
        assertThat(options.isPkcs12Store(), is(equalTo(true)));
        assertThat(options.isPkcs11UseSlotListIndex(), is(equalTo(true)));
        assertThat(config.getKeys("certificate").hasNext(), is(equalTo(false)));
    }

    @Test
    void shouldAddPkcs12CertificateIfDataPresent() throws Exception {
        // Given
        String file = "/path/to/file";
        config.setProperty(PKCS12_FILE_KEY, file);
        String password = "password";
        config.setProperty(PKCS12_PASSWORD_KEY, password);
        int index = 1234;
        config.setProperty(PKCS12_INDEX_KEY, index);
        KeyStoreEntry keyStoreEntry = mock(KeyStoreEntry.class);
        given(keyStores.addPkcs12KeyStore(file, password)).willReturn(keyStoreEntry);
        CertificateEntry certificateEntry = mock(CertificateEntry.class);
        given(keyStoreEntry.getCertificate(index)).willReturn(certificateEntry);
        // When
        options.load(config);
        // Then
        verify(keyStores).addPkcs12KeyStore(file, password);
        verify(keyStores).setActiveCertificate(certificateEntry);
    }

    @Test
    void shouldNotAddPkcs12CertificateIfFileNotPresent() throws Exception {
        // Given
        String file = null;
        config.setProperty(PKCS12_FILE_KEY, file);
        String password = "password";
        config.setProperty(PKCS12_PASSWORD_KEY, password);
        int index = 0;
        config.setProperty(PKCS12_INDEX_KEY, index);
        // When
        options.load(config);
        // Then
        verifyNoInteractions(keyStores);
    }

    @Test
    void shouldNotAddPkcs12CertificateIfPasswordNotPresent() throws Exception {
        // Given
        String file = "/path/to/file";
        config.setProperty(PKCS12_FILE_KEY, file);
        String password = null;
        config.setProperty(PKCS12_PASSWORD_KEY, password);
        int index = 0;
        config.setProperty(PKCS12_INDEX_KEY, index);
        // When
        options.load(config);
        // Then
        verifyNoInteractions(keyStores);
    }

    @Test
    void shouldNotSetActivePkcsCertificateIfIndexNotValid() throws Exception {
        // Given
        String file = "/path/to/file";
        config.setProperty(PKCS12_FILE_KEY, file);
        String password = "password";
        config.setProperty(PKCS12_PASSWORD_KEY, password);
        int index = 1234;
        config.setProperty(PKCS12_INDEX_KEY, index);
        KeyStoreEntry keyStoreEntry = mock(KeyStoreEntry.class);
        given(keyStores.addPkcs12KeyStore(file, password)).willReturn(keyStoreEntry);
        // When
        options.load(config);
        // Then
        verify(keyStores).addPkcs12KeyStore(file, password);
        verify(keyStores, times(0)).setActiveCertificate(any());
    }

    private static ZapXmlConfiguration configWith(String value) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<config>\n"
                        + value
                        + "\n</config>";
        try {
            config.load(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return config;
    }
}
