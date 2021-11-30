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

import java.io.IOException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.cert.CertConfig;
import org.zaproxy.addon.network.internal.cert.CertificateUtils;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The options related to server certificates. */
public class ServerCertificatesOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ServerCertificatesOptions.class);

    /** The default validity, in days, for the root CA certificate. */
    public static final int DEFAULT_ROOT_CA_CERT_VALIDITY = 365;

    /**
     * The default validity, in days, for the server certificates.
     *
     * <p>1 year (with the start adjustment, server certificates are issued 30 days ago). Per:
     *
     * <ul>
     *   <li>https://cabforum.org/2017/02/24/ballot-185-limiting-lifetime-certificates/
     *   <li>and https://www.ssl.com/blogs/apple-limits-ssl-tls-certificate-lifetimes-to-398-days/
     * </ul>
     */
    public static final int DEFAULT_SERVER_CERT_VALIDITY = 368;

    /**
     * The current version of the configurations. Used to keep track of configuration changes
     * between releases, in case changes/updates are needed.
     *
     * <p>It only needs to be incremented for configuration changes (not releases of the add-on).
     *
     * @see #CONFIG_VERSION_KEY
     * @see #updateConfigsImpl(int)
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    private static final String BASE_KEY = "network.serverCertificates";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String ROOT_CA_BASE_KEY = BASE_KEY + ".rootCa.";
    /**
     * The configuration key used to read the encoded {@code KeyStore} containing the root CA
     * certificate and the private key.
     */
    public static final String ROOT_CA_KEY_STORE = ROOT_CA_BASE_KEY + "ks";

    private static final String ROOT_CA_CERT_VALIDITY_DAYS = ROOT_CA_BASE_KEY + "certValidityDays";

    private static final String SERVER_BASE_KEY = BASE_KEY + ".server.";
    private static final String SERVER_CERT_VALIDITY_DAYS = SERVER_BASE_KEY + "certValidityDays";

    private KeyStore rootCaKeyStore;
    private Duration rootCaCertValidity = Duration.ofDays(DEFAULT_ROOT_CA_CERT_VALIDITY);
    private CertConfig rootCaCertConfig = new CertConfig(rootCaCertValidity);

    private Duration serverCertValidity = Duration.ofDays(DEFAULT_SERVER_CERT_VALIDITY);
    private CertConfig serverCertConfig = new CertConfig(serverCertValidity);

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected void parseImpl() {
        // Do always, for now, in case -config arg is in use.
        migrateCoreConfig();

        rootCaKeyStore = createKeyStore(getString(ROOT_CA_KEY_STORE, null));
        int validity = getInt(ROOT_CA_CERT_VALIDITY_DAYS, DEFAULT_ROOT_CA_CERT_VALIDITY);
        if (isInvalidCertValidity(validity)) {
            validity = DEFAULT_ROOT_CA_CERT_VALIDITY;
        }
        rootCaCertValidity = Duration.ofDays(validity);
        rootCaCertConfig = new CertConfig(rootCaCertValidity);

        validity = getInt(SERVER_CERT_VALIDITY_DAYS, DEFAULT_SERVER_CERT_VALIDITY);
        if (isInvalidCertValidity(validity)) {
            validity = DEFAULT_SERVER_CERT_VALIDITY;
        }
        serverCertValidity = Duration.ofDays(validity);
        serverCertConfig = new CertConfig(serverCertValidity);
    }

    private void migrateCoreConfig() {
        String oldConfig = "dynssl.param.rootca";
        String value = getString(oldConfig, "");
        if (!value.isEmpty()) {
            getConfig().setProperty(ROOT_CA_KEY_STORE, value);
        }
        getConfig().clearProperty(oldConfig);
    }

    private static boolean isInvalidCertValidity(Number validity) {
        return validity.intValue() <= 0;
    }

    private KeyStore createKeyStore(String value) {
        if (value == null || value.isEmpty()) {
            return rootCaKeyStore;
        }

        try {
            return CertificateUtils.stringToKeystore(value);
        } catch (IOException e) {
            LOGGER.error("An error occurred while converting from string:", e);
        }
        return null;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    /**
     * Gets the {@code KeyStore} with the root CA certificate and private key.
     *
     * @return the {@code KeyStore}, might be {@code null}.
     */
    public KeyStore getRootCaKeyStore() {
        return rootCaKeyStore;
    }

    /**
     * Sets the {@code KeyStore} with the root CA certificate and private key.
     *
     * @param keyStore the {@code KeyStore}.
     * @throws NullPointerException if the given {@code KeyStore} is {@code null}.
     */
    public void setRootCaKeyStore(KeyStore keyStore) {
        Objects.requireNonNull(keyStore);

        String rootCaCertString;
        try {
            rootCaCertString = CertificateUtils.keyStoreToString(keyStore);
        } catch (IOException e) {
            LOGGER.error("An error occurred while converting to string:", e);
            return;
        }

        getConfig().setProperty(ROOT_CA_KEY_STORE, rootCaCertString);
        rootCaKeyStore = keyStore;
    }

    /**
     * Gets the validity of the root CA certificate, for when generated.
     *
     * @return the validity.
     */
    public Duration getRootCaCertValidity() {
        return rootCaCertValidity;
    }

    /**
     * Sets the validity of the root CA certificate, for when generated.
     *
     * @param validity the validity.
     * @throws IllegalArgumentException if the given validity is less than or equal to 0.
     * @throws NullPointerException if the given {@code validity} is {@code null}.
     */
    public void setRootCaCertValidity(Duration validity) {
        long days = Objects.requireNonNull(validity).toDays();
        if (isInvalidCertValidity(days)) {
            throw new IllegalArgumentException("The validity must be greater than 1 day.");
        }

        getConfig().setProperty(ROOT_CA_CERT_VALIDITY_DAYS, days);

        rootCaCertValidity = validity;
        rootCaCertConfig = new CertConfig(rootCaCertValidity);
    }

    /**
     * Gets the configuration for the root CA certificate.
     *
     * @return the configuration for the root CA certificate, never {@code null}.
     */
    public CertConfig getRootCaCertConfig() {
        return rootCaCertConfig;
    }

    /**
     * Gets the validity of the server certificates, for when generated.
     *
     * @return the validity.
     */
    public Duration getServerCertValidity() {
        return serverCertValidity;
    }

    /**
     * Sets the validity of the server certificates, for when generated.
     *
     * @param validity the validity.
     * @throws IllegalArgumentException if the given validity is less than or equal to 0.
     * @throws NullPointerException if the given {@code validity} is {@code null}.
     */
    public void setServerCertValidity(Duration validity) {
        long days = Objects.requireNonNull(validity).toDays();
        if (isInvalidCertValidity(days)) {
            throw new IllegalArgumentException("The validity must be greater than 1 day.");
        }

        getConfig().setProperty(SERVER_CERT_VALIDITY_DAYS, days);

        serverCertValidity = validity;
        serverCertConfig = new CertConfig(serverCertValidity);
    }

    /**
     * Gets the configuration for the server certificates.
     *
     * @return the configuration for the server certificates, never {@code null}.
     */
    public CertConfig getServerCertConfig() {
        return serverCertConfig;
    }
}
