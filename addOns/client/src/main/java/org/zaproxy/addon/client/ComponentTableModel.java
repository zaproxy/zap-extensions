/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class ComponentTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.type"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.id"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.tagType"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.form"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.href"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".components.table.header.text")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private transient List<ClientSideComponent> components = new ArrayList<>(0);

    public ComponentTableModel() {
        super();
    }

    public void setComponents(List<ClientSideComponent> components) {
        this.components = new ArrayList<>(components.size());

        for (ClientSideComponent token : components) {
            this.components.add(token);
        }

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
        return components.size();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    public ClientSideComponent getComponent(int rowIndex) {
        return components.get(rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ClientSideComponent component = components.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return component.getTypeForDisplay();
            case 1:
                return component.getId();
            case 2:
                return component.getTagType();
            case 3:
                int formId = component.getFormId();
                if (formId >= 0) {
                    return Integer.toString(formId);
                }
                return "";
            case 4:
                if (component.isStorageEvent()) {
                    return component.getParentUrl();
                }
                return component.getHref();
            case 5:
                return component.getText();
            default:
                return null;
        }
    }
}
