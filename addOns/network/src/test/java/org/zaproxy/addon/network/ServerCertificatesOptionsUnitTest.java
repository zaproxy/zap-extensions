/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.zaproxy.addon.network.ServerCertificatesOptions.DEFAULT_ROOT_CA_CERT_VALIDITY;
import static org.zaproxy.addon.network.ServerCertificatesOptions.DEFAULT_SERVER_CERT_VALIDITY;

import java.security.KeyStore;
import java.time.Duration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ServerCertificatesOptions}. */
class ServerCertificatesOptionsUnitTest {

    private static final String CORE_KEY_STORE_KEY = "dynssl.param.rootca";
    private static final String ROOT_CA_KEY_STORE_KEY = "network.serverCertificates.rootCa.ks";
    private static final String ROOT_CA_CERT_VALIDITY_DAYS_KEY =
            "network.serverCertificates.rootCa.certValidityDays";
    private static final String SERVER_CERT_VALIDITY_DAYS_KEY =
            "network.serverCertificates.server.certValidityDays";

    private static final String TEST_KEY_STORE_STR = NetworkTestUtils.FISH_CERT_BASE64_STR;

    private static KeyStore testKeyStore;
    private ServerCertificatesOptions options;

    @BeforeEach
    void setUp() {
        options = new ServerCertificatesOptions();
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        testKeyStore = CertificateUtils.stringToKeystore(TEST_KEY_STORE_STR);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(
                options.getConfigVersionKey(), is(equalTo("network.serverCertificates[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        assertThat(options.getRootCaKeyStore(), is(nullValue()));
        assertThat(
                options.getRootCaCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY))));
        assertThat(
                options.getRootCaCertConfig().getValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY))));
        assertThat(
                options.getServerCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY))));
        assertThat(
                options.getServerCertConfig().getValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY))));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertThat(options.getRootCaKeyStore(), is(nullValue()));
        assertThat(
                options.getRootCaCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY))));
        assertThat(
                options.getRootCaCertConfig().getValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY))));
        assertThat(
                options.getServerCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY))));
        assertThat(
                options.getServerCertConfig().getValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY))));
    }

    @Test
    void shouldLoadConfigWithKeyStore() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(ROOT_CA_KEY_STORE_KEY, TEST_KEY_STORE_STR);
        // When
        options.load(config);
        // Then
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldKeepKeyStoreOnReset(String newKeyStoreString) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(ROOT_CA_KEY_STORE_KEY, TEST_KEY_STORE_STR);
        options.load(config);
        ZapXmlConfiguration cleanConfig = new ZapXmlConfiguration();
        cleanConfig.setProperty(ROOT_CA_KEY_STORE_KEY, newKeyStoreString);
        // When
        options.load(cleanConfig);
        // Then
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
    }

    @Test
    void shouldLoadConfigWithInvalidKeyStore() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(ROOT_CA_KEY_STORE_KEY, "not valid");
        // When
        options.load(config);
        // Then
        assertThat(options.getRootCaKeyStore(), is(nullValue()));
    }

    @Test
    void shouldMigrateCoreKeyStore() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(CORE_KEY_STORE_KEY, TEST_KEY_STORE_STR);
        // When
        options.load(config);
        // Then
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldIgnoreInvalidCoreKeyStore(String keyStore) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(CORE_KEY_STORE_KEY, keyStore);
        // When
        options.load(config);
        // Then
        assertThat(options.getRootCaKeyStore(), is(nullValue()));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = TEST_KEY_STORE_STR)
    void shouldClearCoreKeyStore(String keyStore) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(CORE_KEY_STORE_KEY, keyStore);
        // When
        options.load(config);
        // Then
        assertThat(config.getProperty(CORE_KEY_STORE_KEY), is(nullValue()));
    }

    @Test
    void shouldLoadConfigWithRootCaCertValidity() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(ROOT_CA_CERT_VALIDITY_DAYS_KEY, "60");
        // When
        options.load(config);
        // Then
        assertThat(options.getRootCaCertValidity(), is(equalTo(Duration.ofDays(60))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "0", "" + Long.MAX_VALUE, "A", ""})
    void shouldUseDefaultWithInvalidRootCaCertValidity(String validity) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(ROOT_CA_CERT_VALIDITY_DAYS_KEY, validity);
        // When
        options.load(config);
        // Then
        assertThat(
                options.getRootCaCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY))));
    }

    @Test
    void shouldLoadConfigWithServerCertValidity() {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(SERVER_CERT_VALIDITY_DAYS_KEY, "60");
        // When
        options.load(config);
        // Then
        assertThat(options.getServerCertValidity(), is(equalTo(Duration.ofDays(60))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "0", "" + Long.MAX_VALUE, "A", ""})
    void shouldUseDefaultWithInvalidServerCertValidity(String validity) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        config.setProperty(SERVER_CERT_VALIDITY_DAYS_KEY, validity);
        // When
        options.load(config);
        // Then
        assertThat(
                options.getServerCertValidity(),
                is(equalTo(Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY))));
    }

    @Test
    void shouldSetAndPersistKeyStore() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setRootCaKeyStore(testKeyStore);
        // Then
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
        assertThat(config.getString(ROOT_CA_KEY_STORE_KEY), is(equalTo(TEST_KEY_STORE_STR)));
    }

    @Test
    void shouldThrowExceptionWhenSettingKeyStoreWithoutConfig() throws Exception {
        assertThrows(NullPointerException.class, () -> options.setRootCaKeyStore(testKeyStore));
    }

    @Test
    void shouldNotSetNorPersistEmptyKeyStore() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.setRootCaKeyStore(testKeyStore);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        // When
        options.setRootCaKeyStore(keyStore);
        // Then
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
        assertThat(config.getString(ROOT_CA_KEY_STORE_KEY), is(equalTo(TEST_KEY_STORE_STR)));
    }

    @Test
    void shouldNotSetNorPersistNullKeyStore() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.setRootCaKeyStore(testKeyStore);
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setRootCaKeyStore(null));
        assertThat(options.getRootCaKeyStore(), is(notNullValue()));
        assertThat(config.getString(ROOT_CA_KEY_STORE_KEY), is(equalTo(TEST_KEY_STORE_STR)));
    }

    @Test
    void shouldSetAndPersistRootCaCertValidity() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        // When
        options.setRootCaCertValidity(validity);
        // Then
        assertThat(options.getRootCaCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(ROOT_CA_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getRootCaCertConfig().getValidity(), is(equalTo(validity)));
    }

    @Test
    void shouldThrowExceptionWhenSettingRootCaCertValidityWithoutConfig() throws Exception {
        // Given
        Duration validity = Duration.ofDays(123);
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setRootCaCertValidity(validity));
    }

    @Test
    void shouldNotSetNorPersistNullRootCaCertValidity() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        options.setRootCaCertValidity(validity);
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setRootCaCertValidity(null));
        assertThat(options.getRootCaCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(ROOT_CA_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getRootCaCertConfig().getValidity(), is(equalTo(validity)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0})
    void shouldNotSetNorPersistInvalidRootCaCertValidity(int days) throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        options.setRootCaCertValidity(validity);
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.setRootCaCertValidity(Duration.ofDays(days)));
        assertThat(options.getRootCaCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(ROOT_CA_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getRootCaCertConfig().getValidity(), is(equalTo(validity)));
    }

    @Test
    void shouldSetAndPersistServerCertValidity() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        // When
        options.setServerCertValidity(validity);
        // Then
        assertThat(options.getServerCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(SERVER_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getServerCertConfig().getValidity(), is(equalTo(validity)));
    }

    @Test
    void shouldThrowExceptionWhenSettingServerCertValidityWithoutConfig() throws Exception {
        // Given
        Duration validity = Duration.ofDays(123);
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setServerCertValidity(validity));
    }

    @Test
    void shouldNotSetNorPersistNullServerCertValidity() throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        options.setServerCertValidity(validity);
        // When / Then
        assertThrows(NullPointerException.class, () -> options.setServerCertValidity(null));
        assertThat(options.getServerCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(SERVER_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getServerCertConfig().getValidity(), is(equalTo(validity)));
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0})
    void shouldNotSetNorPersistInvalidServerCertValidity(int days) throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        Duration validity = Duration.ofDays(123);
        options.setServerCertValidity(validity);
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.setServerCertValidity(Duration.ofDays(days)));
        assertThat(options.getServerCertValidity(), is(equalTo(validity)));
        assertThat(config.getLong(SERVER_CERT_VALIDITY_DAYS_KEY), is(equalTo(validity.toDays())));
        assertThat(options.getServerCertConfig().getValidity(), is(equalTo(validity)));
    }
}
