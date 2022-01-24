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
package org.zaproxy.addon.network.internal.cert;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Principal;
import java.util.Arrays;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.security.CertData;
import org.parosproxy.paros.security.SslCertificateService;

/** Unit test for {@link SniX509KeyManager}. */
class SniX509KeyManagerUnitTest {

    private static final String LISTENING_ADDRESS = "127.0.0.2";
    private static final InetAddress LISTENING_INET_ADDRESS;

    static {
        try {
            LISTENING_INET_ADDRESS = InetAddress.getByName(LISTENING_ADDRESS);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private SslCertificateService sslCertificateService;
    private String fallbackHostname;
    private SniX509KeyManager sniX509KeyManager;
    private String keyType;
    private Principal[] issuers;
    private SSLEngine engine;
    private ExtendedSSLSession sslSession;
    private KeyStore keyStore;

    @BeforeEach
    void setup() throws Exception {
        sslCertificateService = mock(SslCertificateService.class);
        fallbackHostname = "example.org";
        sniX509KeyManager =
                new SniX509KeyManager(
                        sslCertificateService, LISTENING_INET_ADDRESS, fallbackHostname);
        keyType = "RSA";
        issuers = null;
        sslSession = mock(ExtendedSSLSession.class);
        engine = mock(SSLEngine.class);
        given(engine.getHandshakeSession()).willReturn(sslSession);
        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
    }

    @Test
    void shouldUseListeningAddressIfNoFallbackHostnameNorSni() throws Exception {
        // Given
        CertData certData = createIpCertData(LISTENING_ADDRESS);
        given(sslCertificateService.createCertForHost(certData)).willReturn(keyStore);
        SniX509KeyManager sniX509KeyManager =
                new SniX509KeyManager(sslCertificateService, LISTENING_INET_ADDRESS, null);
        // When
        sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
        // Then
        verify(sslCertificateService).createCertForHost(certData);
    }

    @Test
    void shouldUseFallbackHostnameIfNoSni() throws Exception {
        // Given
        CertData certData = new CertData(fallbackHostname);
        given(sslCertificateService.createCertForHost(certData)).willReturn(keyStore);
        // When
        sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
        // Then
        verify(sslCertificateService).createCertForHost(certData);
    }

    @Test
    void shouldUseFallbackHostnameAsIpAddress() throws Exception {
        // Given
        fallbackHostname = "127.0.0.4";
        SniX509KeyManager sniX509KeyManager =
                new SniX509KeyManager(
                        sslCertificateService, LISTENING_INET_ADDRESS, fallbackHostname);
        CertData certData = createIpCertData(fallbackHostname);
        given(sslCertificateService.createCertForHost(certData)).willReturn(keyStore);
        // When
        sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
        // Then
        verify(sslCertificateService).createCertForHost(certData);
    }

    @Test
    void shouldUseSni() throws Exception {
        // Given
        String sni = "example.com";
        CertData certData = new CertData(sni);
        given(sslSession.getRequestedServerNames()).willReturn(Arrays.asList(new SNIHostName(sni)));
        given(sslCertificateService.createCertForHost(certData)).willReturn(keyStore);
        // When
        sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
        // Then
        verify(sslCertificateService).createCertForHost(certData);
    }

    @Test
    void shouldUseSniAsIpAddress() throws Exception {
        // Given
        String sni = "127.0.0.5";
        CertData certData = createIpCertData(sni);
        given(sslSession.getRequestedServerNames()).willReturn(Arrays.asList(new SNIHostName(sni)));
        given(sslCertificateService.createCertForHost(certData)).willReturn(keyStore);
        // When
        sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine);
        // Then
        verify(sslCertificateService).createCertForHost(certData);
    }

    @Test
    void shouldThrowIfErrorDuringCertGeneration() throws Exception {
        // Given
        given(sslCertificateService.createCertForHost(any(CertData.class)))
                .willThrow(IOException.class);
        // When / Then
        Exception e =
                assertThrows(
                        GenerationException.class,
                        () -> sniX509KeyManager.chooseEngineServerAlias(keyType, issuers, engine));
        assertThat(e.getMessage(), containsString("Failed to generate the certificate for"));
        assertThat(e.getCause(), is(instanceOf(IOException.class)));
    }

    private static CertData createIpCertData(String address) {
        CertData certData = new CertData();
        certData.addSubjectAlternativeName(new CertData.Name(CertData.Name.IP_ADDRESS, address));
        return certData;
    }
}
