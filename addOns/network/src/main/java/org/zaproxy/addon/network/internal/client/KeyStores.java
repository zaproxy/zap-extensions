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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.EventListenerList;
import org.apache.commons.io.FileUtils;

/** A list of KeyStores. */
public class KeyStores extends AbstractList<KeyStoreEntry> {

    /** The canonical class name of Sun PKCS#11 Provider. */
    public static final String SUN_PKCS11_CANONICAL_CLASS_NAME = "sun.security.pkcs11.SunPKCS11";

    /** The canonical class name of IBMPKCS11Impl Provider. */
    public static final String IBM_PKCS11_CANONICAL_CLASS_NAME =
            "com.ibm.crypto.pkcs11impl.provider.IBMPKCS11Impl";

    /**
     * The name for providers of type PKCS#11.
     *
     * @see #isProviderAvailable(String)
     */
    private static final String PKCS11_PROVIDER_TYPE = "PKCS11";

    /** The name of Sun PKCS#11 Provider. */
    private static final String SUN_PKCS11_PROVIDER_NAME = "SunPKCS11";

    /**
     * The name of the {@code KeyStore} type of Sun PKCS#11 Provider.
     *
     * @see KeyStore#getInstance(String, Provider)
     */
    private static final String SUN_PKCS11_KEYSTORE_TYPE = "PKCS11";

    /**
     * The name of the {@code KeyStore} type of IBMPKCS11Impl Provider.
     *
     * @see KeyStore#getInstance(String, Provider)
     */
    private static final String IBM_PKCS11_KEYSTORE_TYPE = "PKCS11IMPLKS";

    /**
     * Flag that indicates if the check for Java 9 and SunPKCS11 was already done.
     *
     * @see #isJava9SunPkcs11()
     */
    private static Boolean java9SunPkcs11;

    private final EventListenerList eventListeners;
    private ChangeEvent changeEvent;

    private final List<KeyStoreEntry> entries;
    private CertificateEntry activeCertificate;

    public KeyStores() {
        eventListeners = new EventListenerList();

        entries = new ArrayList<>();
    }

    public KeyStoreEntry addPkcs12KeyStore(String path, String password) throws KeyStoresException {
        Objects.requireNonNull(path);
        Objects.requireNonNull(password);

        Path file = Paths.get(path);
        if (Files.notExists(file)) {
            throw new KeyStoresException("The file does not exist: " + file);
        }

        try (InputStream is = Files.newInputStream(file)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(is, password.toCharArray());
            KeyStoreEntry keyStoreEntry =
                    new KeyStoreEntry(
                            KeyStoreEntry.Type.PKCS12,
                            file.getFileName().toString(),
                            keyStore,
                            password);
            entries.add(keyStoreEntry);
            fireStateChanged();
            return keyStoreEntry;
        } catch (Exception e) {
            throw new KeyStoresException("An error occurred while adding the PKCS#12 keystore:", e);
        }
    }

    public KeyStoreEntry addPkcs11KeyStore(String name, String configuration, String password)
            throws KeyStoresException {
        Objects.requireNonNull(configuration);

        if (!isProviderAvailable(PKCS11_PROVIDER_TYPE)) {
            return null;
        }
        try {
            Provider pkcs11 = createPkcs11Provider(configuration);
            Security.addProvider(pkcs11);

            KeyStore keyStore = createPkcs11KeyStore(pkcs11.getName());
            keyStore.load(null, password == null ? null : password.toCharArray());
            KeyStoreEntry keyStoreEntry =
                    new KeyStoreEntry(KeyStoreEntry.Type.PKCS11, name, keyStore, password);
            entries.add(keyStoreEntry);
            fireStateChanged();
            return keyStoreEntry;
        } catch (Exception e) {
            throw new KeyStoresException("An error occurred while adding the PKCS#11 keystore:", e);
        }
    }

    private static Provider createPkcs11Provider(String configuration) throws Exception {
        if (isSunPkcs11Provider()) {
            if (isJava9SunPkcs11()) {
                Provider provider = Security.getProvider(SUN_PKCS11_PROVIDER_NAME);
                Method configure = provider.getClass().getMethod("configure", String.class);
                File configFile = File.createTempFile("pkcs11", ".cfg");
                configFile.deleteOnExit();
                FileUtils.write(configFile, configuration, StandardCharsets.UTF_8);
                return (Provider) configure.invoke(provider, configFile.getAbsolutePath());
            }

            return createInstance(
                    SUN_PKCS11_CANONICAL_CLASS_NAME,
                    InputStream.class,
                    toInputStream(configuration));
        }
        if (isIbmPkcs11Provider()) {
            return createInstance(
                    IBM_PKCS11_CANONICAL_CLASS_NAME,
                    BufferedReader.class,
                    new BufferedReader(new InputStreamReader(toInputStream(configuration))));
        }
        return null;
    }

    private static ByteArrayInputStream toInputStream(String data) {
        return new ByteArrayInputStream(data.getBytes(StandardCharsets.UTF_8));
    }

    private static Provider createInstance(String name, Class<?> paramClass, Object param)
            throws ClassNotFoundException, NoSuchMethodException, InstantiationException,
                    IllegalAccessException, InvocationTargetException {
        Class<?> instanceClass = Class.forName(name);
        Constructor<?> c = instanceClass.getConstructor(new Class<?>[] {paramClass});
        return (Provider) c.newInstance(new Object[] {param});
    }

    private static boolean isSunPkcs11Provider() {
        try {
            Class.forName(SUN_PKCS11_CANONICAL_CLASS_NAME);
            return true;
        } catch (Throwable ignore) {
        }
        return false;
    }

    private static boolean isJava9SunPkcs11() {
        if (java9SunPkcs11 != null) {
            return java9SunPkcs11;
        }

        java9SunPkcs11 = Boolean.FALSE;
        try {
            Provider provider = Security.getProvider(SUN_PKCS11_PROVIDER_NAME);
            if (provider != null) {
                provider.getClass().getMethod("configure", String.class);
                java9SunPkcs11 = Boolean.TRUE;
            }
        } catch (NoSuchMethodException ignore) {
            // The provider/method is available only in Java 9+.
        }
        return java9SunPkcs11;
    }

    private static boolean isIbmPkcs11Provider() {
        try {
            Class.forName(IBM_PKCS11_CANONICAL_CLASS_NAME);
            return true;
        } catch (Throwable ignore) {
        }
        return false;
    }

    private static KeyStore createPkcs11KeyStore(String providerName) throws KeyStoreException {
        String keyStoreType = SUN_PKCS11_KEYSTORE_TYPE;
        if (isIbmPkcs11Provider()) {
            keyStoreType = IBM_PKCS11_KEYSTORE_TYPE;
        }
        return KeyStore.getInstance(keyStoreType, Security.getProvider(providerName));
    }

    private static boolean isProviderAvailable(String type) {
        try {
            if (type.equals(PKCS11_PROVIDER_TYPE)) {
                try {
                    Class.forName(SUN_PKCS11_CANONICAL_CLASS_NAME);
                    return true;
                } catch (Throwable ignore) {
                    Class.forName(IBM_PKCS11_CANONICAL_CLASS_NAME);
                    return true;
                }
            }

            if (type.equals("msks")) {
                Class.forName("se.assembla.jce.provider.ms.MSProvider");
                return true;
            }
        } catch (Throwable ignore) {
        }
        return false;
    }

    /**
     * Gets the active certificate.
     *
     * @return the active certificate, might be {@code null}.
     */
    public CertificateEntry getActiveCertificate() {
        return activeCertificate;
    }

    /**
     * Sets the active certificate.
     *
     * <p>Listeners are notified of the change.
     *
     * @param certificate the certificate, might be {@code null}.
     */
    public void setActiveCertificate(CertificateEntry certificate) {
        if (activeCertificate == certificate) {
            return;
        }

        if (activeCertificate != null) {
            activeCertificate.invalidateSession();
        }
        activeCertificate = certificate;
        fireStateChanged();
    }

    /**
     * Adds the given listener to be notified when a KeyStore is added or removed, and when the
     * active certificate changes.
     *
     * @param listener the listener to add.
     */
    public void addChangeListener(ChangeListener listener) {
        eventListeners.add(ChangeListener.class, listener);
    }

    /**
     * Removes the given listener.
     *
     * @param listener the listener to remove.
     */
    public void removeChangeListener(ChangeListener listener) {
        eventListeners.remove(ChangeListener.class, listener);
    }

    private void fireStateChanged() {
        Object[] listeners = eventListeners.getListenerList();
        for (int i = listeners.length - 2; i >= 0; i -= 2) {
            if (listeners[i] == ChangeListener.class) {
                if (changeEvent == null) {
                    changeEvent = new ChangeEvent(this);
                }
                ((ChangeListener) listeners[i + 1]).stateChanged(changeEvent);
            }
        }
    }

    @Override
    public KeyStoreEntry get(int index) {
        return entries.get(index);
    }

    @Override
    public int size() {
        return entries.size();
    }

    @Override
    public KeyStoreEntry remove(int index) {
        KeyStoreEntry keyStoreEntry = entries.remove(index);
        if (activeCertificate != null && activeCertificate.getParent() == keyStoreEntry) {
            activeCertificate = null;
        }
        fireStateChanged();
        return keyStoreEntry;
    }

    @Override
    public int hashCode() {
        return entries.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return entries.equals(o);
    }
}
