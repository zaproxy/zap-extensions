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
package org.zaproxy.addon.network.internal.client.apachev5.h2;

import java.net.SocketAddress;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import org.apache.hc.client5.http.ssl.HttpClientHostnameVerifier;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.http.ssl.TlsCiphers;
import org.apache.hc.core5.http2.ssl.H2TlsSupport;
import org.apache.hc.core5.net.NamedEndpoint;
import org.apache.hc.core5.reactor.ssl.SSLBufferMode;
import org.apache.hc.core5.reactor.ssl.TransportSecurityLayer;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.client.CertificateEntry;
import org.zaproxy.addon.network.internal.client.KeyStores;
import org.zaproxy.addon.network.internal.client.LaxTrustManager;

/**
 * A {@link TlsStrategy} that allows to trust all certificates, use a client certificate, or verify
 * all certificates.
 */
public class ZapClientTlsStrategy implements TlsStrategy {

    private static final Logger LOGGER = LogManager.getLogger(ZapClientTlsStrategy.class);

    private static final String[] APPLICATION_PROTOCOL = {TlsUtils.APPLICATION_PROTOCOL_HTTP_2};

    private static final TrustManager[] LAX_TRUST_MANAGER =
            new TrustManager[] {new LaxTrustManager()};
    private static final HostnameVerifier ACCEPT_ALL_NAMES = (host, cert) -> true;

    private static final String SSL = "SSL";

    private final boolean strict;
    private final ConnectionOptions options;
    private final ClientCertificatesOptions clientCertificatesOptions;
    private final KeyStores keyStores;
    private final SSLContext strictSslContext;
    private final SSLContext laxSslContext;

    private final HostnameVerifier hostnameVerifier;
    private CertificateEntry activeCertificate;
    private SSLContext activeCertificateSslContext;

    public ZapClientTlsStrategy(
            boolean strict,
            ConnectionOptions options,
            ClientCertificatesOptions clientCertificatesOptions) {
        this.strict = strict;
        this.strictSslContext = createSslContext(null);
        this.laxSslContext = createSslContext(LAX_TRUST_MANAGER);
        this.hostnameVerifier =
                strict ? HttpsSupport.getDefaultHostnameVerifier() : ACCEPT_ALL_NAMES;

        this.options = options;
        this.clientCertificatesOptions = clientCertificatesOptions;

        keyStores = clientCertificatesOptions.getKeyStores();
        keyStores.addChangeListener(
                e -> {
                    CertificateEntry currentActiveCertificate = keyStores.getActiveCertificate();
                    if (currentActiveCertificate != activeCertificate) {
                        activeCertificate = currentActiveCertificate;
                        applyActiveCertificate();
                    }
                });
        activeCertificate = keyStores.getActiveCertificate();
        applyActiveCertificate();
    }

    private void applyActiveCertificate() {
        activeCertificateSslContext =
                activeCertificate == null ? null : activeCertificate.getSslContext();
    }

    private SSLContext getSslContext() {
        if (strict) {
            return strictSslContext;
        }

        SSLContext clientCertificateSslContext = activeCertificateSslContext;
        if (clientCertificateSslContext != null && clientCertificatesOptions.isUseCertificate()) {
            return clientCertificateSslContext;
        }
        return laxSslContext;
    }

    private static SSLContext createSslContext(TrustManager[] trustManagers) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SSL);
            SecureRandom random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            sslContext.init(null, trustManagers, random);
            return sslContext;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    @Override
    @Deprecated
    public boolean upgrade(
            final TransportSecurityLayer tlsSession,
            final HttpHost host,
            final SocketAddress localAddress,
            final SocketAddress remoteAddress,
            final Object attachment,
            final Timeout handshakeTimeout) {
        upgrade(tlsSession, host, attachment, handshakeTimeout, null);
        return true;
    }

    @Override
    public void upgrade(
            final TransportSecurityLayer tlsSession,
            final NamedEndpoint endpoint,
            final Object attachment,
            final Timeout handshakeTimeout,
            final FutureCallback<TransportSecurityLayer> callback) {

        tlsSession.startTls(
                getSslContext(),
                endpoint,
                SSLBufferMode.STATIC,
                (e, sslEngine) -> {
                    SSLParameters sslParameters = sslEngine.getSSLParameters();
                    sslParameters.setProtocols(options.getTlsProtocols().toArray(new String[0]));
                    sslParameters.setCipherSuites(
                            TlsCiphers.excludeH2Blacklisted(sslParameters.getCipherSuites()));
                    H2TlsSupport.setEnableRetransmissions(sslParameters, false);
                    sslParameters.setApplicationProtocols(APPLICATION_PROTOCOL);
                    sslEngine.setSSLParameters(sslParameters);

                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug(
                                "Enabled protocols: {}",
                                Arrays.asList(sslEngine.getEnabledProtocols()));
                        LOGGER.debug(
                                "Enabled cipher suites:{}",
                                Arrays.asList(sslEngine.getEnabledCipherSuites()));
                        LOGGER.debug("Starting handshake ({})", handshakeTimeout);
                    }
                },
                (e, sslEngine) -> {
                    verifySession(endpoint.getHostName(), sslEngine.getSession());
                    return null;
                },
                handshakeTimeout,
                callback);
    }

    private void verifySession(String hostName, SSLSession session) throws SSLException {
        final Certificate[] certs = session.getPeerCertificates();
        if (certs.length < 1) {
            throw new SSLPeerUnverifiedException("Peer certificate chain is empty");
        }
        final Certificate peerCertificate = certs[0];
        final X509Certificate x509Certificate;
        if (peerCertificate instanceof X509Certificate) {
            x509Certificate = (X509Certificate) peerCertificate;
        } else {
            throw new SSLPeerUnverifiedException(
                    "Unexpected certificate type: " + peerCertificate.getType());
        }
        if (hostnameVerifier instanceof HttpClientHostnameVerifier) {
            ((HttpClientHostnameVerifier) hostnameVerifier).verify(hostName, x509Certificate);
        } else if (!hostnameVerifier.verify(hostName, session)) {
            throw new SSLPeerUnverifiedException(
                    "Certificate for <"
                            + hostName
                            + "> doesn't match any "
                            + "of the subject alternative names.");
        }
    }
}
