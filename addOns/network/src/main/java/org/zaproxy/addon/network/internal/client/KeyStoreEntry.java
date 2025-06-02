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
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A keystore, provides its name, type, and the certificates. */
public class KeyStoreEntry {

    private static final Logger LOGGER = LogManager.getLogger(KeyStoreEntry.class);

    /** The type of keystores supported. */
    public enum Type {
        PKCS11("PKCS#11"),
        PKCS12("PKCS#12");

        private final String name;

        private Type(String name) {
            this.name = name;
        }

        @Override
        public String toString() {
            return name;
        }
    }

    private static Boolean ibmPkcs11Provider;

    private final String name;
    private final Type type;
    private final KeyStore keyStore;
    private final List<CertificateEntry> certificates;

    KeyStoreEntry(Type type, String name, KeyStore keyStore, String password)
            throws KeyStoresException {
        this.type = Objects.requireNonNull(type);
        this.name = type + ": " + Objects.requireNonNull(name);
        this.keyStore = Objects.requireNonNull(keyStore);

        this.certificates = Collections.unmodifiableList(readCertificates(this, keyStore));
        this.certificates.forEach(
                e -> {
                    if (!e.unlock(password)) {
                        LOGGER.warn("Failed to unlock certificate: {}", e.getName());
                    }
                });
    }

    /**
     * Gets the type of the keystore.
     *
     * @return the type, never {@code null}.
     */
    public Type getType() {
        return type;
    }

    /**
     * Gets the name of the keystore.
     *
     * @return the name, never {@code null}.
     */
    public String getName() {
        return name;
    }

    KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Gets the certificate at the given index of the keystore.
     *
     * @param index the index of the certificate.
     * @return the certificate, might be {@code null}.
     */
    public CertificateEntry getCertificate(int index) {
        if (index < 0 || index >= certificates.size()) {
            return null;
        }
        return certificates.get(index);
    }

    /**
     * Gets the certificates of the keystore.
     *
     * @return the certificates.
     */
    public List<CertificateEntry> getCertificates() {
        return certificates;
    }

    private static List<CertificateEntry> readCertificates(KeyStoreEntry parent, KeyStore keyStore)
            throws KeyStoresException {
        List<CertificateEntry> certificates = new ArrayList<>();
        try {
            Enumeration<String> en = keyStore.aliases();

            boolean ibmProvider = isIbmPKCS11Provider();
            while (en.hasMoreElements()) {
                String alias = en.nextElement();
                // Sun's and IBM's KeyStore implementations behave differently...
                // With IBM's KeyStore impl #getCertificate(String) returns null when
                // #isKeyEntry(String) returns true.
                // If IBM add all certificates and let the user choose the correct one.
                if (keyStore.isKeyEntry(alias)
                        || (ibmProvider && keyStore.isCertificateEntry(alias))) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    // IBM: Maybe we should check the KeyUsage?
                    // ((X509Certificate) cert).getKeyUsage()[0]
                    certificates.add(
                            new CertificateEntry(parent, certificate, alias, certificates.size()));
                }
            }
        } catch (KeyStoreException e) {
            throw new KeyStoresException(e);
        }
        return certificates;
    }

    private static boolean isIbmPKCS11Provider() {
        if (ibmPkcs11Provider != null) {
            return ibmPkcs11Provider;
        }

        ibmPkcs11Provider = false;
        try {
            Class.forName(KeyStores.IBM_PKCS11_CANONICAL_CLASS_NAME);
            ibmPkcs11Provider = true;
        } catch (Throwable ignore) {
        }
        return ibmPkcs11Provider;
    }

    @Override
    public String toString() {
        return name;
    }
}
