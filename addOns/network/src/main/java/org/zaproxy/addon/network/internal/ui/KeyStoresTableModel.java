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

import javax.swing.event.ChangeEvent;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.client.KeyStores;

/** A table model for KeyStores. */
@SuppressWarnings("serial")
public class KeyStoresTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString(
                "network.ui.options.clientcertificates.keystore.keystores.table.header")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private KeyStores keyStores;

    public void setKeyStores(KeyStores keyStores) {
        if (this.keyStores != null) {
            this.keyStores.removeChangeListener(this::keyStoresChanged);
        }

        this.keyStores = keyStores;

        if (keyStores != null) {
            keyStores.addChangeListener(this::keyStoresChanged);
        }

        fireTableDataChanged();
    }

    private void keyStoresChanged(ChangeEvent e) {
        fireTableDataChanged();
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    @Override
    public int getRowCount() {
        if (keyStores == null) {
            return 0;
        }
        return keyStores.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (keyStores == null) {
            return null;
        }
        return keyStores.get(rowIndex);
    }
}
