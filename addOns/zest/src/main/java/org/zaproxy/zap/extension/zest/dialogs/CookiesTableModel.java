/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.dialogs;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class CookiesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("zest.cookies.table.domain"),
        Constant.messages.getString("zest.cookies.table.name"),
        Constant.messages.getString("zest.cookies.table.value"),
        Constant.messages.getString("zest.cookies.table.path")
    };

    private List<String[]> values = new ArrayList<>();

    /** */
    public CookiesTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return values.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        Object[] value = this.values.get(row);
        return value[col];
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }

    @Override
    public void setValueAt(Object value, int row, int col) {
        if (col == 1) {
            this.values.get(row)[col] = (String) value;
            fireTableCellUpdated(row, col);
        }
    }

    @Override
    public String getColumnName(int col) {
        return columnNames[col];
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    public List<String[]> getValues() {
        return values;
    }

    public String getValue(String name) {
        return this.getValue(name, null);
    }

    public String getValue(String name, String defaultValue) {
        for (String[] nvPair : this.values) {
            if (nvPair[0].equals(name)) {
                return nvPair[1];
            }
        }
        return defaultValue;
    }

    public void setValues(List<String[]> values) {
        this.values = values;
    }

    public void clear() {
        this.values.clear();
    }

    public void add(String domain, String name, String value, String path) {
        this.values.add(new String[] {domain, name, value, path});
        this.fireTableRowsInserted(this.values.size() - 1, this.values.size() - 1);
    }

    public void replace(int index, String domain, String name, String value, String path) {
        if (index < this.values.size()) {
            this.values.get(index)[0] = domain;
            this.values.get(index)[1] = name;
            this.values.get(index)[2] = value;
            this.values.get(index)[3] = path;
            this.fireTableRowsInserted(index, index);
        }
    }

    public void remove(int index) {
        if (index < this.values.size()) {
            this.values.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
