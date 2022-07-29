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
package org.zaproxy.zap.extension.selenium;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

@SuppressWarnings("serial")
public class OptionsBrowserExtensionsTableModel
        extends AbstractMultipleOptionsTableModel<BrowserExtension> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("selenium.options.extensions.table.header.enabled"),
        Constant.messages.getString("selenium.options.extensions.table.header.browser"),
        Constant.messages.getString("selenium.options.extensions.table.header.extension")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<BrowserExtension> extensions = new ArrayList<>(0);

    public OptionsBrowserExtensionsTableModel() {
        super();
    }

    @Override
    public List<BrowserExtension> getElements() {
        return extensions;
    }

    public void setExtensions(List<BrowserExtension> proxies) {
        this.extensions = new ArrayList<>(proxies.size());

        for (BrowserExtension proxy : proxies) {
            this.extensions.add(new BrowserExtension(proxy));
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
        if (c == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public int getRowCount() {
        return extensions.size();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
            case 0:
                return getElement(rowIndex).isEnabled();
            case 1:
                return ExtensionSelenium.getName(getElement(rowIndex).getBrowser());
            case 2:
                return getElement(rowIndex).getPath().toFile().getName();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && aValue instanceof Boolean) {
            extensions.get(rowIndex).setEnabled((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
