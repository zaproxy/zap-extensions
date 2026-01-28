/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium.internal;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;

@SuppressWarnings("serial")
public class CustomBrowsersTableModel
        extends AbstractMultipleOptionsBaseTableModel<CustomBrowserImpl> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("selenium.options.custom.browsers.table.header.name"),
        Constant.messages.getString("selenium.options.custom.browsers.table.header.driver"),
        Constant.messages.getString("selenium.options.custom.browsers.table.header.binary"),
        Constant.messages.getString("selenium.options.custom.browsers.table.header.type")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<CustomBrowserImpl> browsers;

    public CustomBrowsersTableModel() {
        browsers = new ArrayList<>(0);
    }

    @Override
    public List<CustomBrowserImpl> getElements() {
        return browsers;
    }

    public void setBrowsers(List<CustomBrowserImpl> browsers) {
        this.browsers = new ArrayList<>(browsers.size());

        for (CustomBrowserImpl browser : browsers) {
            this.browsers.add(new CustomBrowserImpl(browser));
        }

        fireTableDataChanged();
    }

    @Override
    public String getColumnName(int columnIndex) {
        return COLUMN_NAMES[columnIndex];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public int getRowCount() {
        return browsers.size();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CustomBrowserImpl browser = getElement(rowIndex);
        switch (columnIndex) {
            case 0:
                return browser.getName();
            case 1:
                return browser.getDriverPath();
            case 2:
                return browser.getBinaryPath();
            case 3:
                return browser.getBrowserType().toString();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        // Not editable
    }
}
