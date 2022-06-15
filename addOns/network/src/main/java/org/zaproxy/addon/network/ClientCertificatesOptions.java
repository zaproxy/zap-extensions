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
package org.zaproxy.addon.network;

import java.util.Objects;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.client.CertificateEntry;
import org.zaproxy.addon.network.internal.client.KeyStoreEntry;
import org.zaproxy.addon.network.internal.client.KeyStores;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** The options related to client certificates. */
public class ClientCertificatesOptions extends VersionedAbstractParam {

    private static final Logger LOGGER = LogManager.getLogger(ClientCertificatesOptions.class);

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

    private static final String BASE_KEY = "network.clientCertificates";

    /**
     * The configuration key for the version of the configurations.
     *
     * @see #CURRENT_CONFIG_VERSION
     */
    private static final String CONFIG_VERSION_KEY = BASE_KEY + VERSION_ATTRIBUTE;

    private static final String USE_CERTIFICATE_KEY = BASE_KEY + ".use";

    private static final String PKCS12_BASE_KEY = BASE_KEY + ".pkcs12.";

    private static final String PKCS12_FILE_KEY = PKCS12_BASE_KEY + "file";
    private static final String PKCS12_PASSWORD_KEY = PKCS12_BASE_KEY + "password";
    private static final String PKCS12_INDEX_KEY = PKCS12_BASE_KEY + "index";
    private static final String PKCS12_STORE_KEY = PKCS12_BASE_KEY + "store";

    private static final String PKCS11_BASE_KEY = BASE_KEY + ".pkcs11.";
    private static final String PKCS11_USE_SLI_KEY = PKCS11_BASE_KEY + "useSli";

    private final KeyStores keyStores;

    private boolean useCertificate;

    private String pkcs12File = "";
    private String pkcs12Password = "";
    private int pkcs12Index;
    private boolean pkcs12Store;

    private boolean pkcs11UseSlotListIndex;

    ClientCertificatesOptions() {
        this(new KeyStores());
    }

    ClientCertificatesOptions(KeyStores keyStores) {
        this.keyStores = keyStores;
    }

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
        migrateCoreConfigs();

        pkcs12File = getString(PKCS12_FILE_KEY, "");
        pkcs12Password = getString(PKCS12_PASSWORD_KEY, "");
        pkcs12Index = Math.max(0, getInt(PKCS12_INDEX_KEY, 0));
        pkcs12Store = getBoolean(PKCS12_STORE_KEY, false);

        pkcs11UseSlotListIndex = getBoolean(PKCS11_USE_SLI_KEY, false);

        useCertificate = getBoolean(USE_CERTIFICATE_KEY, false);

        if (!pkcs12File.isEmpty() && !pkcs12Password.isEmpty()) {
            addPkcs12Certificate();
        }
    }

    /**
     * Gets the {@code KeyStore}s available, their certificates, and the active certificate.
     *
     * @return the KeyStores.
     */
    public KeyStores getKeyStores() {
        return keyStores;
    }

    boolean addPkcs12Certificate() {
        try {
            KeyStoreEntry keyStoreEntry = keyStores.addPkcs12KeyStore(pkcs12File, pkcs12Password);
            CertificateEntry certificateEntry = keyStoreEntry.getCertificate(pkcs12Index);
            if (certificateEntry == null) {
                LOGGER.warn(
                        "Certificate not found in the keystore, using index {}, total certificates: {}",
                        pkcs12Index,
                        keyStoreEntry.getCertificates().size());
                return false;
            }
            keyStores.setActiveCertificate(certificateEntry);
            return true;
        } catch (Exception e) {
            LOGGER.warn("An error occurred while setting the active certificate:", e);
            return false;
        }
    }

    private void migrateCoreConfigs() {
        migrateConfig("certificate.use", USE_CERTIFICATE_KEY);
        migrateConfig("certificate.pkcs12.path", PKCS12_FILE_KEY);
        migrateConfig("certificate.pkcs12.password", PKCS12_PASSWORD_KEY);
        migrateConfig("certificate.pkcs12.index", PKCS12_INDEX_KEY);
        migrateConfig("certificate.persist", PKCS12_STORE_KEY);
        migrateConfig("certificate.experimentalSlotListIndex", PKCS11_USE_SLI_KEY);

        ((HierarchicalConfiguration) getConfig()).clearTree("certificate");
    }

    private void migrateConfig(String oldConfig, String newConfig) {
        Object oldValue = getConfig().getProperty(oldConfig);
        if (oldValue != null) {
            getConfig().setProperty(newConfig, oldValue);
            getConfig().clearProperty(oldConfig);
        }
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Nothing to do.
    }

    /**
     * Tells whether or not to use a client certificate.
     *
     * @return {@code true} to use a client certificate, {@code false} otherwise.
     */
    public boolean isUseCertificate() {
        return useCertificate;
    }

    /**
     * Sets whether or not to use a client certificate.
     *
     * @param use {@code true} to use a client certificate, {@code false} otherwise.
     */
    public void setUseCertificate(boolean use) {
        useCertificate = use;
        getConfig().setProperty(USE_CERTIFICATE_KEY, useCertificate);
    }

    /**
     * Gets the PKCS#12 file.
     *
     * @return the file, never {@code null}.
     */
    public String getPkcs12File() {
        return pkcs12File;
    }

    /**
     * Sets the PKCS#12 file.
     *
     * @param file the file.
     * @throws NullPointerException if the given {@code pkcs12File} is {@code null}.
     */
    public void setPkcs12File(String file) {
        pkcs12File = Objects.requireNonNull(file);
    }

    /**
     * Gets the password for the PKCS#12 file.
     *
     * @return the file, never {@code null}.
     */
    public String getPkcs12Password() {
        return pkcs12Password;
    }

    /**
     * Sets the password for the PKCS#12 file.
     *
     * @param password the password.
     * @throws NullPointerException if the given {@code pkcs12Password} is {@code null}.
     */
    public void setPkcs12Password(String password) {
        pkcs12Password = Objects.requireNonNull(password);
    }

    /**
     * Sets the certificate index of the PKCS#12 file.
     *
     * @param index the index.
     */
    public void setPkcs12Index(int index) {
        pkcs12Index = Math.max(0, index);
    }

    /**
     * Gets the certificate index of the PKCS#12 file
     *
     * @return the index.
     */
    public int getPkcs12Index() {
        return pkcs12Index;
    }

    /**
     * Tells whether or not to store the PKCS#12 configurations.
     *
     * @return {@code true} to store the PKCS#12 configurations, {@code false} otherwise.
     */
    public boolean isPkcs12Store() {
        return pkcs12Store;
    }

    /**
     * Sets whether or not to store the PKCS#12 configurations.
     *
     * @param store {@code true} to store the PKCS#12 configurations, {@code false} otherwise.
     */
    public void setPkcs12Store(boolean store) {
        pkcs12Store = store;

        if (pkcs12Store) {
            getConfig().setProperty(PKCS12_FILE_KEY, pkcs12File);
            getConfig().setProperty(PKCS12_PASSWORD_KEY, pkcs12Password);
            getConfig().setProperty(PKCS12_INDEX_KEY, pkcs12Index);
        } else {
            getConfig().setProperty(PKCS12_FILE_KEY, "");
            getConfig().setProperty(PKCS12_PASSWORD_KEY, "");
            getConfig().setProperty(PKCS12_INDEX_KEY, 0);
        }
        getConfig().setProperty(PKCS12_STORE_KEY, pkcs12Store);
    }

    /**
     * Tells whether or not to use the slot list index for PKCS#11.
     *
     * @return {@code true} to use the slot list index, {@code false} otherwise.
     */
    public boolean isPkcs11UseSlotListIndex() {
        return pkcs11UseSlotListIndex;
    }

    /**
     * Sets whether or not to use the slot list index for PKCS#11.
     *
     * @param use {@code true} to use the slot list index, {@code false} otherwise.
     */
    public void setPkcs11UseSlotListIndex(boolean use) {
        pkcs11UseSlotListIndex = use;
        getConfig().setProperty(PKCS11_USE_SLI_KEY, pkcs11UseSlotListIndex);
    }
}
