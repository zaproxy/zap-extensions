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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.parosproxy.paros.security.CertData;
import org.zaproxy.addon.network.NetworkTestUtils;

/** Unit test for {@link CertificateUtils}. */
class CertificateUtilsUnitTest {

    private static final String CERTIFICATE_PEM =
            CertificateUtils.BEGIN_CERTIFICATE_TOKEN
                    + "\n"
                    + NetworkTestUtils.FISH_CERT_BASE64
                    + CertificateUtils.END_CERTIFICATE_TOKEN
                    + "\n";

    private static final String CERT_DATA = "Certificate data...";
    private static final String CERT_DATA_BASE64 =
            Base64.getEncoder().encodeToString(CERT_DATA.getBytes(StandardCharsets.US_ASCII));

    private static final String PRIV_KEY_DATA = "Private key...";
    private static final String PRIV_KEY_BASE64 =
            Base64.getEncoder().encodeToString(PRIV_KEY_DATA.getBytes(StandardCharsets.US_ASCII));

    @Test
    void shouldCreateRootCaKeyStoreWithGivenValidity() {
        // Given
        Duration validity = Duration.ofDays(60);
        CertConfig config = new CertConfig(validity);
        // When
        KeyStore keyStore = CertificateUtils.createRootCaKeyStore(config);
        // Then
        assertThat(keyStore, is(notNullValue()));
        Date certNotAfter = CertificateUtils.getCertificate(keyStore).getNotAfter();
        Date certExpiredDate =
                new Date(System.currentTimeMillis() + validity.plusDays(1L).toMillis());
        assertThat(certNotAfter.before(certExpiredDate), is(equalTo(true)));
    }

    @Test
    void shouldCreateServerCertificateWithCommonName() throws Exception {
        // Given
        CertConfig config = new CertConfig(Duration.ofDays(60));
        KeyStore rootCaKeyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        X509Certificate rootCaCert = CertificateUtils.getCertificate(rootCaKeyStore);
        PublicKey rootCaPublicKey = rootCaCert.getPublicKey();
        PrivateKey rooCaPrivateKey = CertificateUtils.getPrivateKey(rootCaKeyStore);
        CertData certData = new CertData("example.org");
        // When
        KeyStore keyStore =
                CertificateUtils.createServerKeyStore(
                        rootCaCert, rootCaPublicKey, rooCaPrivateKey, certData, 1L, config);
        // Then
        assertThat(keyStore, is(notNullValue()));
        assertThat(
                CertificateUtils.getCertificate(keyStore).getSubjectX500Principal().getName(),
                containsString("CN=example.org"));
    }

    @Test
    void shouldCreateServerCertificateWithAlternativeNames() throws Exception {
        // Given
        Duration validity = Duration.ofDays(60);
        CertConfig config = new CertConfig(validity);
        KeyStore rootCaKeyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        X509Certificate rootCaCert = CertificateUtils.getCertificate(rootCaKeyStore);
        PublicKey rootCaPublicKey = rootCaCert.getPublicKey();
        PrivateKey rooCaPrivateKey = CertificateUtils.getPrivateKey(rootCaKeyStore);
        CertData certData = new CertData();
        certData.addSubjectAlternativeName(new CertData.Name(CertData.Name.DNS, "example.org"));
        certData.addSubjectAlternativeName(
                new CertData.Name(CertData.Name.IP_ADDRESS, "127.0.0.1"));
        // When
        KeyStore keyStore =
                CertificateUtils.createServerKeyStore(
                        rootCaCert, rootCaPublicKey, rooCaPrivateKey, certData, 1L, config);
        // Then
        assertThat(keyStore, is(notNullValue()));
        X509Certificate serverCert = CertificateUtils.getCertificate(keyStore);
        assertThat(
                serverCert.getSubjectAlternativeNames().toString(),
                containsString("[[2, example.org], [7, 127.0.0.1]]"));
    }

    @Test
    void shouldCreateServerCertificateWithGivenValidity() throws Exception {
        // Given
        Duration validity = Duration.ofDays(60);
        CertConfig config = new CertConfig(validity);
        KeyStore rootCaKeyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        X509Certificate rootCaCert = CertificateUtils.getCertificate(rootCaKeyStore);
        PublicKey rootCaPublicKey = rootCaCert.getPublicKey();
        PrivateKey rooCaPrivateKey = CertificateUtils.getPrivateKey(rootCaKeyStore);
        CertData certData = new CertData("example.org");
        // When
        KeyStore keyStore =
                CertificateUtils.createServerKeyStore(
                        rootCaCert, rootCaPublicKey, rooCaPrivateKey, certData, 1L, config);
        // Then
        assertThat(keyStore, is(notNullValue()));
        Date certNotAfter = CertificateUtils.getCertificate(keyStore).getNotAfter();
        Date certExpiredDate =
                new Date(System.currentTimeMillis() + validity.plusDays(1L).toMillis());
        assertThat(certNotAfter.before(certExpiredDate), is(equalTo(true)));
    }

    @Test
    void shouldCreateServerCertificateWithGivenSerialNumber() throws Exception {
        // Given
        Duration validity = Duration.ofDays(60);
        CertConfig config = new CertConfig(validity);
        KeyStore rootCaKeyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        X509Certificate rootCaCert = CertificateUtils.getCertificate(rootCaKeyStore);
        PublicKey rootCaPublicKey = rootCaCert.getPublicKey();
        PrivateKey rooCaPrivateKey = CertificateUtils.getPrivateKey(rootCaKeyStore);
        CertData certData = new CertData("example.org");
        // When
        KeyStore keyStore =
                CertificateUtils.createServerKeyStore(
                        rootCaCert, rootCaPublicKey, rooCaPrivateKey, certData, 10L, config);
        // Then
        assertThat(keyStore, is(notNullValue()));
        assertThat(
                CertificateUtils.getCertificate(keyStore).getSerialNumber(),
                is(equalTo(BigInteger.TEN)));
    }

    @Test
    void shouldThrowExceptionwhenCreatingServerCertificateWithoutCommonOrAlternativeNames()
            throws Exception {
        // Given
        Duration validity = Duration.ofDays(60);
        CertConfig config = new CertConfig(validity);
        KeyStore rootCaKeyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        X509Certificate rootCaCert = CertificateUtils.getCertificate(rootCaKeyStore);
        PublicKey rootCaPublicKey = rootCaCert.getPublicKey();
        PrivateKey rooCaPrivateKey = CertificateUtils.getPrivateKey(rootCaKeyStore);
        CertData certData = new CertData();
        // When / Then
        assertThrows(
                GenerationException.class,
                () ->
                        CertificateUtils.createServerKeyStore(
                                rootCaCert,
                                rootCaPublicKey,
                                rooCaPrivateKey,
                                certData,
                                10L,
                                config));
    }

    @Test
    void shouldReturnEmptyByteArrayIfNotAbleToFindCertSectionInPemData() {
        // Given
        String pem = CERT_DATA_BASE64;
        // When
        byte[] cert = CertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfBeginCertTokenWasNotFoundInPemData() {
        // Given
        String pem = CERT_DATA_BASE64 + CertificateUtils.END_CERTIFICATE_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfEndCertTokenWasNotFoundInPemData() {
        // Given
        String pem = CertificateUtils.BEGIN_CERTIFICATE_TOKEN + CERT_DATA_BASE64;
        // When
        byte[] cert = CertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfEndCertTokenIsBeforeBeginCertTokenInPemData() {
        // Given
        String pem =
                CertificateUtils.END_CERTIFICATE_TOKEN
                        + CERT_DATA_BASE64
                        + CertificateUtils.BEGIN_CERTIFICATE_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnCertificateBetweenBeginAndEndCertTokensFromPemData() {
        // Given
        String pem =
                CertificateUtils.BEGIN_CERTIFICATE_TOKEN
                        + CERT_DATA_BASE64
                        + CertificateUtils.END_CERTIFICATE_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractCertificate(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(CERT_DATA.length())));
        assertThat(cert, is(equalTo(CERT_DATA.getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void shouldReturnEmptyByteArrayIfNotAbleToFindPrivKeySectionInPemData() {
        // Given
        String pem = PRIV_KEY_BASE64;
        // When
        byte[] cert = CertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfBeginPrivKeyTokenWasNotFoundInPemData() {
        // Given
        String pem = PRIV_KEY_BASE64 + CertificateUtils.END_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfEndPrivKeyTokenWasNotFoundInPemData() {
        // Given
        String pem = CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN + PRIV_KEY_BASE64;
        // When
        byte[] cert = CertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnEmptyByteArrayIfEndPrivKeyTokenIsBeforeBeginPrivKeyTokenInPemData() {
        // Given
        String pem =
                CertificateUtils.END_PRIVATE_KEY_TOKEN
                        + PRIV_KEY_BASE64
                        + CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(0)));
    }

    @Test
    void shouldReturnPrivateKeyBetweenBeginAndEndPrivKeyTokensFromPemData() {
        // Given
        String pem =
                CertificateUtils.BEGIN_PRIVATE_KEY_TOKEN
                        + PRIV_KEY_BASE64
                        + CertificateUtils.END_PRIVATE_KEY_TOKEN;
        // When
        byte[] cert = CertificateUtils.extractPrivateKey(pem);
        // Then
        assertThat(cert, is(notNullValue()));
        assertThat(cert.length, is(equalTo(PRIV_KEY_DATA.length())));
        assertThat(cert, is(equalTo(PRIV_KEY_DATA.getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void shouldConvertPemToKeystore() throws Exception {
        // Given
        byte[] cert = Base64.getMimeDecoder().decode(NetworkTestUtils.FISH_CERT_BASE64);
        byte[] key = Base64.getMimeDecoder().decode(NetworkTestUtils.FISH_PRIV_KEY_BASE64);
        // When
        KeyStore keyStore = CertificateUtils.pemToKeyStore(cert, key);
        // Then
        assertThat(keyStore, is(notNullValue()));
    }

    @Test
    void shouldConvertStringCertToAndFromKeyStore() throws Exception {
        // Given
        String certBase64 = NetworkTestUtils.FISH_CERT_BASE64_STR;
        // When
        KeyStore keyStore = CertificateUtils.stringToKeystore(certBase64);
        String newCertBase64 = CertificateUtils.keyStoreToString(keyStore);
        // Then
        assertThat(newCertBase64, is(equalTo(certBase64)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldReturnNullWhenConvertingNullOrEmptyStringCertToKeyStore(String certBase64)
            throws Exception {
        // Given / When
        KeyStore keyStore = CertificateUtils.stringToKeystore(certBase64);
        // Then
        assertThat(keyStore, is(nullValue()));
    }

    @Test
    void shouldThrowExceptionWhenConvertingMalformedBase64StringToKeyStore() throws Exception {
        // Given
        String certNotBase64 = "something not Base64 encoded";
        // When / Then
        assertThrows(IOException.class, () -> CertificateUtils.stringToKeystore(certNotBase64));
    }

    @Test
    void shouldThrowExceptionWhenConvertingMalformedStringToKeyStore() throws Exception {
        // Given
        String certNotBase64 =
                Base64.getUrlEncoder()
                        .encodeToString("not a KeyStore".getBytes(StandardCharsets.US_ASCII));
        // When / Then
        assertThrows(IOException.class, () -> CertificateUtils.stringToKeystore(certNotBase64));
    }

    @Test
    void shouldConvertKeyStoreToCertificatePemString() throws Exception {
        // Given
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        // When
        String pem = CertificateUtils.keyStoreToCertificatePem(keyStore);
        // Then
        assertThat(pem, is(equalTo(CERTIFICATE_PEM)));
    }

    @Test
    void shouldReturnEmptyStringWhenConvertingNullKeyStoreToCertificatePemString()
            throws Exception {
        // Given
        KeyStore keyStore = null;
        // When
        String pem = CertificateUtils.keyStoreToCertificatePem(keyStore);
        // Then
        assertThat(pem, is(equalTo("")));
    }

    @Test
    void shouldReturnEmptyStringWhenConvertingEmptyKeyStoreToCertificatePemString()
            throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        // When
        String pem = CertificateUtils.keyStoreToCertificatePem(keyStore);
        // Then
        assertThat(pem, is(equalTo("")));
    }

    @Test
    void shouldConvertKeyStoreToCertificatePemFile() throws Exception {
        // Given
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        Path file = Files.createTempFile("cert", ".cer");
        // When
        CertificateUtils.keyStoreToCertificatePem(keyStore, file);
        // Then
        assertThat(contents(file), is(equalTo(CERTIFICATE_PEM)));
    }

    @Test
    void shouldCreateEmptyFileWhenConvertingNullKeyStoreToCertificatePemString() throws Exception {
        // Given
        KeyStore keyStore = null;
        Path file = Files.createTempFile("cert", ".cer");
        // When
        CertificateUtils.keyStoreToCertificatePem(keyStore, file);
        // Then
        assertThat(contents(file), is(equalTo("")));
    }

    @Test
    void shouldCreateEmptyFileWhenConvertingEmptyKeyStoreToCertificatePemString() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        Path file = Files.createTempFile("cert", ".cer");
        // When
        CertificateUtils.keyStoreToCertificatePem(keyStore, file);
        // Then
        assertThat(contents(file), is(equalTo("")));
    }

    @Test
    void shouldGetCertificateFromKeyStore() throws Exception {
        // Given
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        // When
        X509Certificate certificate = CertificateUtils.getCertificate(keyStore);
        // Then
        assertThat(certificate, is(notNullValue()));
    }

    @Test
    void shouldReturnNullWhenGettingCertificateFromEmptyKeyStore() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        // When
        X509Certificate certificate = CertificateUtils.getCertificate(keyStore);
        // Then
        assertThat(certificate, is(nullValue()));
    }

    @Test
    void shouldReturnNullWhenGettingCertificateFromNullKeyStore() throws Exception {
        // Given
        KeyStore keyStore = null;
        // When
        X509Certificate certificate = CertificateUtils.getCertificate(keyStore);
        // Then
        assertThat(certificate, is(nullValue()));
    }

    @Test
    void shouldGetPrivateKeyFromKeyStore() throws Exception {
        // Given
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        // When
        PrivateKey privateKey = CertificateUtils.getPrivateKey(keyStore);
        // Then
        assertThat(privateKey, is(notNullValue()));
    }

    @Test
    void shouldReturnNullWhenGettingPrivateKeyFromEmptyKeyStore() throws Exception {
        // Given
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        // When
        PrivateKey privateKey = CertificateUtils.getPrivateKey(keyStore);
        // Then
        assertThat(privateKey, is(nullValue()));
    }

    @Test
    void shouldReturnNullWhenGettingPrivateKeyFromNullKeyStore() throws Exception {
        // Given
        KeyStore keyStore = null;
        // When
        PrivateKey privateKey = CertificateUtils.getPrivateKey(keyStore);
        // Then
        assertThat(privateKey, is(nullValue()));
    }

    @Test
    void shouldConvertKeyStoreToCertificateAndPrivateKeyPemFile() throws Exception {
        // Given
        KeyStore keyStore =
                CertificateUtils.stringToKeystore(NetworkTestUtils.FISH_CERT_BASE64_STR);
        Path file = Files.createTempFile("cert", ".cer");
        // When
        CertificateUtils.keyStoreToCertificateAndPrivateKeyPem(keyStore, file);
        // Then
        String pem = new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
        byte[] certificate = CertificateUtils.extractCertificate(pem);
        assertThat(certificate.length, is(not(0)));
        byte[] privateKey = CertificateUtils.extractPrivateKey(pem);
        assertThat(privateKey.length, is(not(0)));
        assertThat(CertificateUtils.pemToKeyStore(certificate, privateKey), is(notNullValue()));
    }

    private static String contents(Path file) throws IOException {
        return new String(Files.readAllBytes(file), StandardCharsets.US_ASCII);
    }
}
