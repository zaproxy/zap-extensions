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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.HttpsSupport;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.CertificateEntry;
import org.zaproxy.addon.network.internal.client.KeyStores;
import org.zaproxy.addon.network.internal.client.LaxTrustManager;

/**
 * A {@link LayeredConnectionSocketFactory} that allows to trust all certificates, use a client
 * certificate, or verify all certificates.
 */
public class SslConnectionSocketFactory implements LayeredConnectionSocketFactory {

    static final String LAX_ATTR_NAME = "zap.ssl.lax";

    private static final Logger LOGGER = LogManager.getLogger(SslConnectionSocketFactory.class);

    private static final TrustManager[] LAX_TRUST_MANAGER =
            new TrustManager[] {new LaxTrustManager()};
    private static final HostnameVerifier ACCEPT_ALL_NAMES = (host, cert) -> true;

    private static final String SSL = "SSL";

    private final ConnectionOptions connectionOptions;
    private final ClientCertificatesOptions clientCertificatesOptions;

    private final KeyStores keyStores;

    private final SSLConnectionSocketFactory strictSslConnectionSocketFactory;
    private final SSLConnectionSocketFactory laxSslConnectionSocketFactory;

    private CertificateEntry activeCertificate;
    private SSLConnectionSocketFactory activeCertificateSslConnectionSocketFactory;

    public SslConnectionSocketFactory(
            ConnectionOptions connectionOptions,
            ClientCertificatesOptions clientCertificatesOptions) {
        this.connectionOptions = connectionOptions;
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

        strictSslConnectionSocketFactory =
                new SSLConnectionSocketFactory(
                        createSslSocketFactory(null), HttpsSupport.getDefaultHostnameVerifier());
        laxSslConnectionSocketFactory =
                createLaxSslSocketFactory(createSslSocketFactory(LAX_TRUST_MANAGER));
    }

    private void applyActiveCertificate() {
        activeCertificateSslConnectionSocketFactory =
                activeCertificate == null
                        ? null
                        : createLaxSslSocketFactory(activeCertificate.getSocketFactory());
    }

    private static SSLSocketFactory createSslSocketFactory(TrustManager[] trustManagers) {
        try {
            SSLContext sslContext = SSLContext.getInstance(SSL);
            SecureRandom random = new SecureRandom();
            random.setSeed(System.currentTimeMillis());
            sslContext.init(null, trustManagers, random);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    private SSLConnectionSocketFactory createLaxSslSocketFactory(SSLSocketFactory socketFactory) {
        return new SSLConnectionSocketFactory(socketFactory, ACCEPT_ALL_NAMES) {

            @Override
            protected void prepareSocket(SSLSocket socket) throws IOException {
                socket.setEnabledProtocols(
                        connectionOptions.getTlsProtocols().toArray(new String[0]));
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
            }
        };
    }

    @Override
    public Socket createSocket(HttpContext context) throws IOException {
        return getSslConnectionSocketFactory(context).createSocket(context);
    }

    private LayeredConnectionSocketFactory getSslConnectionSocketFactory(HttpContext context) {
        if (!isLax(context)) {
            return strictSslConnectionSocketFactory;
        }

        LayeredConnectionSocketFactory clientCertificateSocketFactory =
                activeCertificateSslConnectionSocketFactory;
        if (clientCertificateSocketFactory != null
                && clientCertificatesOptions.isUseCertificate()) {
            return clientCertificateSocketFactory;
        }
        return laxSslConnectionSocketFactory;
    }

    private static boolean isLax(HttpContext context) {
        return Boolean.TRUE.equals(context.getAttribute(LAX_ATTR_NAME));
    }

    @Override
    public Socket createLayeredSocket(Socket socket, String target, int port, HttpContext context)
            throws IOException {
        return createLayeredSocket(socket, target, port, null, context);
    }

    @Override
    public Socket createLayeredSocket(
            Socket socket, String target, int port, Object attachment, HttpContext context)
            throws IOException {
        return getSslConnectionSocketFactory(context)
                .createLayeredSocket(socket, target, port, attachment, context);
    }

    @Override
    public Socket connectSocket(
            TimeValue connectTimeout,
            Socket socket,
            HttpHost host,
            InetSocketAddress remoteAddress,
            InetSocketAddress localAddress,
            HttpContext context)
            throws IOException {
        Timeout timeout =
                connectTimeout != null
                        ? Timeout.of(connectTimeout.getDuration(), connectTimeout.getTimeUnit())
                        : null;
        return connectSocket(socket, host, remoteAddress, localAddress, timeout, timeout, context);
    }

    @Override
    public Socket connectSocket(
            final Socket socket,
            final HttpHost host,
            final InetSocketAddress remoteAddress,
            final InetSocketAddress localAddress,
            final Timeout connectTimeout,
            final Object attachment,
            final HttpContext context)
            throws IOException {

        return getSslConnectionSocketFactory(context)
                .connectSocket(
                        socket,
                        host,
                        remoteAddress,
                        localAddress,
                        connectTimeout,
                        attachment,
                        context);
    }
}
