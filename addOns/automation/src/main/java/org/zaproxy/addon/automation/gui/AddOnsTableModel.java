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
package org.zaproxy.addon.automation.gui;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class AddOnsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.addon.table.header.addons")
    };

    private List<String> addOns = new ArrayList<>();

    public AddOnsTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return addOns.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        return this.addOns.get(row);
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    public List<String> getAddOns() {
        return addOns;
    }

    public void setAddOns(List<String> addOns) {
        if (addOns == null) {
            this.addOns = new ArrayList<>();
        } else {
            this.addOns = addOns;
        }
    }

    public void clear() {
        this.addOns.clear();
    }

    public void add(String addOn) {
        this.addOns.add(addOn);
        this.fireTableRowsInserted(this.addOns.size() - 1, this.addOns.size() - 1);
    }

    public void remove(int index) {
        if (index < this.addOns.size()) {
            this.addOns.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
