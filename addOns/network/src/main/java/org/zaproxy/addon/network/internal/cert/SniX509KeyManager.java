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

import io.netty.util.NetUtil;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Objects;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.security.CertData;
import org.parosproxy.paros.security.SslCertificateService;

/**
 * A key manager for generated server certificates.
 *
 * <p>Attempts to use the SNI provided in the SSL/TLS handshake, falling back to the requested
 * hostname or the address of the server.
 */
public class SniX509KeyManager extends X509ExtendedKeyManager {

    private static final Logger LOGGER = LogManager.getLogger(SniX509KeyManager.class);

    private final SslCertificateService sslCertificateService;
    private final String fallbackHostname;
    private InetAddress listeningAddress;
    private X509KeyManager x509KeyManager;

    /**
     * Constructs a {@code SniX509KeyManager} with the given data.
     *
     * @param sslCertificateService the service used to generate the server certificates.
     * @param listeningAddress the address the server is listening to.
     * @param fallbackHostname the hostname to use if none was provided during the SSL/TLS handshake
     *     (SNI).
     * @throws NullPointerException if the given {@code sslCertificateService} or {@code
     *     listeningAddress} is null.
     */
    public SniX509KeyManager(
            SslCertificateService sslCertificateService,
            InetAddress listeningAddress,
            String fallbackHostname) {
        this.sslCertificateService = Objects.requireNonNull(sslCertificateService);
        this.listeningAddress = Objects.requireNonNull(listeningAddress);
        this.fallbackHostname = fallbackHostname;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        if (x509KeyManager == null) {
            createX509KeyManager(engine);
        }
        return x509KeyManager.chooseServerAlias(keyType, issuers, null);
    }

    private void createX509KeyManager(SSLEngine engine) {
        SSLSession session = engine.getHandshakeSession();
        if (session == null) {
            LOGGER.warn("No handshake session to extract the domain.");
        }

        String hostname = extractHostname(session);
        if (hostname == null) {
            LOGGER.debug(
                    "No domain extracted from handshake session, fallback to: {}",
                    fallbackHostname);
            hostname = fallbackHostname;
        } else {
            LOGGER.debug("Domain extracted from handshake session: {}", hostname);
        }

        KeyManagerFactory keyManagerFactory = null;
        try {
            keyManagerFactory =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

            initKeyManagerFactoryWithCertForHostname(
                    sslCertificateService, keyManagerFactory, hostname, listeningAddress);
        } catch (GeneralSecurityException | IOException e) {
            logAndThrow(
                    "Failed to generate the certificate for '"
                            + hostname
                            + "' caused by: "
                            + e.getMessage(),
                    e);
        }

        x509KeyManager = getX509KeyManager(keyManagerFactory.getKeyManagers());
        if (x509KeyManager == null) {
            logAndThrow(
                    "No X509KeyManager found in: "
                            + Arrays.toString(keyManagerFactory.getKeyManagers()));
        }
    }

    private static void logAndThrow(String message) {
        logAndThrow(message, null);
    }

    private static void logAndThrow(String message, Throwable cause) {
        LOGGER.warn(message, cause);
        throw new GenerationException(message, cause);
    }

    private static X509KeyManager getX509KeyManager(KeyManager[] keyManagers) {
        for (int i = 0; i < keyManagers.length; i++) {
            KeyManager keyManager = keyManagers[i];
            if (keyManager instanceof X509KeyManager) {
                return (X509KeyManager) keyManager;
            }
        }
        return null;
    }

    private static String extractHostname(SSLSession sslSession) {
        if (sslSession instanceof ExtendedSSLSession) {
            for (SNIServerName serverName :
                    ((ExtendedSSLSession) sslSession).getRequestedServerNames()) {
                if (serverName.getType() == StandardConstants.SNI_HOST_NAME) {
                    return ((SNIHostName) serverName).getAsciiName();
                }
            }
        }
        return null;
    }

    private static void initKeyManagerFactoryWithCertForHostname(
            SslCertificateService sslCertificateService,
            KeyManagerFactory keyManagerFactory,
            String hostname,
            InetAddress listeningAddress)
            throws GeneralSecurityException, IOException {

        boolean hostnameIsIpAddress = isIpAddress(hostname);

        CertData certData = hostnameIsIpAddress ? new CertData() : new CertData(hostname);
        if (hostname == null) {
            certData.addSubjectAlternativeName(
                    new CertData.Name(CertData.Name.IP_ADDRESS, listeningAddress.getHostAddress()));
        }

        if (hostnameIsIpAddress) {
            certData.addSubjectAlternativeName(
                    new CertData.Name(CertData.Name.IP_ADDRESS, hostname));
        }

        KeyStore ks = sslCertificateService.createCertForHost(certData);
        keyManagerFactory.init(ks, SslCertificateService.PASSPHRASE);
    }

    private static boolean isIpAddress(String value) {
        return value != null
                && !value.isEmpty()
                && (NetUtil.isValidIpV4Address(value) || NetUtil.isValidIpV6Address(value));
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return x509KeyManager.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return x509KeyManager.getPrivateKey(alias);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return null;
    }
}
