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
package org.zaproxy.addon.network.internal.ui;

import java.util.List;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxModel;
import org.zaproxy.addon.network.internal.client.Pkcs11Driver;
import org.zaproxy.addon.network.internal.client.Pkcs11Drivers;

/** A {@link ComboBoxModel} of {@link Pkcs11Driver}s. */
@SuppressWarnings("serial")
public class DriversComboBoxModel extends AbstractListModel<Pkcs11Driver>
        implements ComboBoxModel<Pkcs11Driver> {

    private static final long serialVersionUID = 1L;

    private final List<Pkcs11Driver> drivers;
    private Pkcs11Driver selectedDriver;

    public DriversComboBoxModel(Pkcs11Drivers drivers) {
        this.drivers = drivers;
        selectedDriver = getFirstAvailable();

        drivers.addChangeListener(
                e -> {
                    if (selectedDriver != null) {
                        if (!drivers.contains(selectedDriver)) {
                            selectedDriver = getFirstAvailable();
                        }
                    } else {
                        selectedDriver = getFirstAvailable();
                    }
                    fireContentsChanged(this, 0, drivers.size());
                });
    }

    private Pkcs11Driver getFirstAvailable() {
        return !drivers.isEmpty() ? drivers.get(0) : null;
    }

    @Override
    public int getSize() {
        return drivers.size();
    }

    @Override
    public Pkcs11Driver getElementAt(int index) {
        return drivers.get(index);
    }

    @Override
    public void setSelectedItem(Object anItem) {
        selectedDriver = (Pkcs11Driver) anItem;
        fireContentsChanged(this, -1, -1);
    }

    @Override
    public Pkcs11Driver getSelectedItem() {
        return selectedDriver;
    }
}
