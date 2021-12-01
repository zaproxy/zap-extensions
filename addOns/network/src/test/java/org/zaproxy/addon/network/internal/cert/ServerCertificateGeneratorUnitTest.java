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
package org.zaproxy.addon.network.internal.cert;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Date;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.security.CertData;
import org.zaproxy.addon.network.NetworkTestUtils;
import org.zaproxy.addon.network.ServerCertificatesOptions;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ServerCertificateGenerator}. */
class ServerCertificateGeneratorUnitTest {

    private static KeyStore testKeyStore;
    private static ServerCertificatesOptions options;

    @BeforeAll
    static void beforeAll() throws Exception {
        testKeyStore = CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        options = new ServerCertificatesOptions();
    }

    @Test
    void shouldCreateGeneratorWithKeyStoreAndOptions() {
        assertDoesNotThrow(() -> new ServerCertificateGenerator(testKeyStore, options));
    }

    @Test
    void shouldThrowExceptionWhenCreatingGeneratorWithNullKeyStore() {
        // Given
        KeyStore keyStore = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ServerCertificateGenerator(keyStore, options));
    }

    @Test
    void shouldThrowExceptionWhenCreatingGeneratorWithEmptyKeyStore() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ServerCertificateGenerator(keyStore, options));
    }

    @Test
    void shouldThrowExceptionWhenCreatingGeneratorWithNullOptions() {
        // Given
        ServerCertificatesOptions options = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new ServerCertificateGenerator(testKeyStore, options));
    }

    @Test
    void shouldGenerateCertificate() {
        // Given
        ServerCertificateGenerator generator =
                new ServerCertificateGenerator(testKeyStore, options);
        CertData certData = new CertData("example.com");
        // When
        KeyStore certKeyStore = generator.generate(certData);
        // Then
        assertThat(certKeyStore, is(notNullValue()));
    }

    @Test
    void shouldGenerateCertificateWithServerCertConfig() {
        // Given
        ServerCertificatesOptions options = new ServerCertificatesOptions();
        options.load(new ZapXmlConfiguration());
        Duration validity = Duration.ofDays(90L);
        options.setServerCertValidity(validity);
        ServerCertificateGenerator generator =
                new ServerCertificateGenerator(testKeyStore, options);
        CertData certData = new CertData("example.com");
        // When
        KeyStore certKeyStore = generator.generate(certData);
        // Then
        assertThat(certKeyStore, is(notNullValue()));
        Date certNotAfter = CertificateUtils.getCertificate(certKeyStore).getNotAfter();
        Date certExpiredDate =
                new Date(System.currentTimeMillis() + validity.plusDays(1L).toMillis());
        assertThat(certNotAfter.before(certExpiredDate), is(equalTo(true)));
    }

    @Test
    void shouldReturnSameGeneratedCertificateIfPreviouslyGenerated() {
        // Given
        ServerCertificateGenerator generator =
                new ServerCertificateGenerator(testKeyStore, options);
        CertData certData = new CertData("example.com");
        // When
        KeyStore certKeyStoreFirstTime = generator.generate(certData);
        KeyStore certKeyStoreSecondTime = generator.generate(certData);
        // Then
        assertThat(certKeyStoreFirstTime, is(notNullValue()));
        assertThat(certKeyStoreSecondTime, is(sameInstance(certKeyStoreFirstTime)));
    }

    @Test
    void shouldThrowExceptionWhenGeneratingWithNullCertData() {
        // Given
        ServerCertificateGenerator generator =
                new ServerCertificateGenerator(testKeyStore, options);
        CertData certData = null;
        // When / Then
        assertThrows(NullPointerException.class, () -> generator.generate(certData));
    }

    @Test
    void shouldGenerateCertificatesWithSequentialSerials() {
        // Given
        ServerCertificateGenerator generator =
                new ServerCertificateGenerator(testKeyStore, options);
        CertData certDataFirst = new CertData("example.com");
        CertData certDataSecond = new CertData("example.org");
        // When
        KeyStore certKeyStoreFirst = generator.generate(certDataFirst);
        KeyStore certKeyStoreSecond = generator.generate(certDataSecond);
        // Then
        assertThat(certKeyStoreFirst, is(notNullValue()));
        BigInteger firstSerial =
                CertificateUtils.getCertificate(certKeyStoreFirst).getSerialNumber();
        assertThat(certKeyStoreSecond, is(notNullValue()));
        BigInteger secondSerial =
                CertificateUtils.getCertificate(certKeyStoreSecond).getSerialNumber();
        assertThat(secondSerial, is(equalTo(firstSerial.add(BigInteger.ONE))));
    }
}
