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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.EventListenerList;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.HierarchicalConfiguration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.ui.Pkcs11DriversDialog;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** A list of PKCS#11 drivers, loaded from a configuration file. */
public class Pkcs11Drivers extends AbstractList<Pkcs11Driver> {

    private static final Logger LOGGER = LogManager.getLogger(Pkcs11Drivers.class);

    private static final String DRIVERS_FILENAME = "pkcs11-drivers.xml";

    private final EventListenerList eventListeners;
    private ChangeEvent changeEvent;

    private Path driversFile;
    private List<Pkcs11Driver> drivers;

    /**
     * Constructs a {@code Pkcs11Drivers} using the default drivers file, either the one in the home
     * directory or the one bundled in the add-on.
     */
    public Pkcs11Drivers() {
        eventListeners = new EventListenerList();

        driversFile = Paths.get(Constant.getZapHome(), DRIVERS_FILENAME);

        if (Files.exists(driversFile)) {
            try {
                drivers = loadDrivers(new ZapXmlConfiguration(driversFile.toFile()));
            } catch (Exception e) {
                LOGGER.warn("Failed to read the drivers from {}", driversFile, e);
                driversFile = null;
            }
        } else {
            driversFile = null;
        }

        if (driversFile == null) {
            try {
                drivers =
                        loadDrivers(
                                new ZapXmlConfiguration(
                                        Pkcs11DriversDialog.class.getResource(
                                                "/" + DRIVERS_FILENAME)));
            } catch (ConfigurationException e) {
                LOGGER.error("Failed to read the drivers from internal drivers file.", e);
                drivers = new ArrayList<>();
            }
        }
    }

    private static List<Pkcs11Driver> loadDrivers(ZapXmlConfiguration configuration) {
        List<Pkcs11Driver> drivers = new ArrayList<>();
        for (HierarchicalConfiguration conf : configuration.configurationsAt("driver")) {
            drivers.add(
                    new Pkcs11Driver(
                            conf.getString("name", ""),
                            conf.getString("path", ""),
                            getInt(conf.getString("slot")),
                            getInt(conf.getString("slotListIndex"))));
        }
        return drivers;
    }

    private static int getInt(String value) {
        if (value != null && !value.isEmpty()) {
            try {
                return Math.max(0, Integer.parseInt(value));
            } catch (NumberFormatException e) {
                LOGGER.warn("Failed to parse an integer from: {}", value);
            }
        }
        return 0;
    }

    /**
     * Saves the drivers to the default drivers file.
     *
     * <p>The listeners are notified of changes.
     *
     * @see #addChangeListener(ChangeListener)
     */
    public void save() {
        save0();
        fireStateChanged();
    }

    private void save0() {
        if (driversFile == null) {
            return;
        }

        ZapXmlConfiguration configuration = new ZapXmlConfiguration();
        configuration.setRootElementName("driverConfiguration");

        for (int i = 0; i < drivers.size(); i++) {
            Pkcs11Driver driver = drivers.get(i);
            String baseKey = "driver(" + i + ").";
            configuration.setProperty(baseKey + "name", driver.getName());
            configuration.setProperty(baseKey + "path", driver.getLibrary());
            configuration.setProperty(baseKey + "slot", driver.getSlot());
            configuration.setProperty(baseKey + "slotListIndex", driver.getSlotListIndex());
        }

        try {
            configuration.save(driversFile.toFile());
        } catch (ConfigurationException e) {
            LOGGER.error("Failed to save the drivers to {}", driversFile, e);
        }
    }

    /**
     * Adds the given listener to be notified when the changes are saved.
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
    public Pkcs11Driver get(int index) {
        return drivers.get(index);
    }

    @Override
    public int size() {
        return drivers.size();
    }

    @Override
    public Pkcs11Driver set(int index, Pkcs11Driver element) {
        return drivers.set(index, element);
    }

    @Override
    public void add(int index, Pkcs11Driver element) {
        drivers.add(index, element);
    }

    @Override
    public Pkcs11Driver remove(int index) {
        return drivers.remove(index);
    }

    @Override
    public int hashCode() {
        return drivers.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return drivers.equals(o);
    }
}
