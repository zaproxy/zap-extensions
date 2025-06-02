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

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.X509KeyManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A {@link X509KeyManager} for a single alias. */
public class SingleAliasKeyManager implements X509KeyManager {

    private static final Logger LOGGER = LogManager.getLogger(SingleAliasKeyManager.class);

    private final KeyStore keyStore;
    private final String[] alias;
    private final char[] password;

    public SingleAliasKeyManager(KeyStore keyStore, String alias, char[] password) {
        this.keyStore = Objects.requireNonNull(keyStore);
        Objects.requireNonNull(alias);
        this.alias = new String[] {alias};
        Objects.requireNonNull(password);
        this.password = password;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        } catch (Exception e) {
            LOGGER.warn("Failed to get the private key:", e);
        }
        return null;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias[0];
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias[0];
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        try {
            Certificate[] certificateChain = keyStore.getCertificateChain(alias);
            if (certificateChain == null) {
                return null;
            }
            X509Certificate[] x509CertificateChain = new X509Certificate[certificateChain.length];
            System.arraycopy(certificateChain, 0, x509CertificateChain, 0, certificateChain.length);
            return x509CertificateChain;
        } catch (KeyStoreException e) {
            LOGGER.warn("Failed to get the certificate chain:", e);
        }
        return null;
    }
}
