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
package org.zaproxy.zap.extension.selenium.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

@SuppressWarnings("serial")
public class BrowserArgumentsTableModel extends AbstractMultipleOptionsTableModel<BrowserArgument> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("selenium.options.browser.arguments.table.header.enabled"),
        Constant.messages.getString("selenium.options.browser.arguments.table.header.argument")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<BrowserArgument> arguments;

    public BrowserArgumentsTableModel() {
        arguments = new ArrayList<>(0);
    }

    @Override
    public List<BrowserArgument> getElements() {
        return arguments;
    }

    public String getArgumentsAsString() {
        return arguments.stream()
                .filter(BrowserArgument::isEnabled)
                .map(BrowserArgument::getArgument)
                .collect(Collectors.joining(" "));
    }

    public void setArguments(List<BrowserArgument> args) {
        arguments = new ArrayList<>(args.size());

        for (BrowserArgument arg : args) {
            arguments.add(new BrowserArgument(arg));
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
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public int getRowCount() {
        return arguments.size();
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
                return getElement(rowIndex).getArgument();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && aValue instanceof Boolean) {
            arguments.get(rowIndex).setEnabled((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }
}
