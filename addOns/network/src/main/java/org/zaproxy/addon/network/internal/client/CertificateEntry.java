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

import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A certificate of a {@link KeyStoreEntry}. */
public class CertificateEntry {

    private static final Logger LOGGER = LogManager.getLogger(CertificateEntry.class);

    private static final TrustManager[] LAX_TRUST_MANAGER =
            new TrustManager[] {new LaxTrustManager()};

    private final KeyStoreEntry parent;
    private final Certificate certificate;
    private final String alias;
    private final String name;
    private final int index;
    private SSLContext sslContext;

    CertificateEntry(KeyStoreEntry parent, Certificate certificate, String alias, int index) {
        this.parent = Objects.requireNonNull(parent);
        this.certificate = Objects.requireNonNull(certificate);
        this.alias = Objects.requireNonNull(alias);
        this.name = extractName(certificate, alias);
        this.index = index;
    }

    public KeyStoreEntry getParent() {
        return parent;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public String getName() {
        return name;
    }

    public int getIndex() {
        return index;
    }

    public boolean isUnlocked() {
        return sslContext != null;
    }

    public boolean unlock(String password) {
        KeyStore keyStore = parent.getKeyStore();
        SingleAliasKeyManager keyManager =
                new SingleAliasKeyManager(keyStore, alias, password.toCharArray());

        if (keyManager.getPrivateKey(alias) == null) {
            return false;
        }

        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(new KeyManager[] {keyManager}, LAX_TRUST_MANAGER, new SecureRandom());
            return true;
        } catch (Exception e) {
            LOGGER.error(
                    "An error occurred while initialising the SSLContext: {}", e.getMessage(), e);
            sslContext = null;
            return false;
        }
    }

    public SSLSocketFactory getSocketFactory() {
        if (sslContext == null) {
            return null;
        }
        return sslContext.getSocketFactory();
    }

    void invalidateSession() {
        if (sslContext == null) {
            return;
        }

        invalidateSession(sslContext.getClientSessionContext());
        invalidateSession(sslContext.getServerSessionContext());
    }

    private static void invalidateSession(SSLSessionContext session) {
        if (session == null) {
            return;
        }

        int timeout = session.getSessionTimeout();
        session.setSessionTimeout(1);
        session.setSessionTimeout(timeout);
    }

    private static String extractName(Certificate certificate, String alias) {
        String cn = getCn(certificate);
        if (cn == null || cn.isEmpty()) {
            return alias;
        }
        return cn + " [" + alias + "]";
    }

    private static String getCn(Certificate certificate) {
        String dn = certificate.toString();
        int i = 0;
        i = dn.indexOf("CN=");
        if (i == -1) {
            return null;
        }
        dn = dn.substring(i + 3);

        char[] dnChars = dn.toCharArray();
        for (i = 0; i < dnChars.length; i++) {
            if (dnChars[i] == ',' && i > 0 && dnChars[i - 1] != '\\') {
                break;
            }
        }
        return dn.substring(0, i);
    }

    @Override
    public String toString() {
        return name;
    }
}
