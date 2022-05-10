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
package org.zaproxy.addon.automation.gui;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class CustomHeadersTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.customheader.table.header.name"),
        Constant.messages.getString("automation.dialog.customheader.table.header.value")
    };

    private List<CustomHeader> customHeaders = new ArrayList<>();

    public CustomHeadersTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return customHeaders.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        CustomHeader ch = this.customHeaders.get(row);
        if (ch != null) {
            switch (col) {
                case 0:
                    return ch.getName();
                case 1:
                    return ch.getValue();
                default:
                    return null;
            }
        }
        return null;
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

    public List<CustomHeader> getCustomHeaders() {
        return customHeaders;
    }

    public Map<String, String> getCustomHeadersMap() {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (CustomHeader ch : customHeaders) {
            map.put(ch.getName(), ch.getValue());
        }
        return map;
    }

    public void setCustomHeaders(Map<?, ?> map) {
        this.clear();
        if (map != null) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                this.customHeaders.add(
                        new CustomHeader((String) entry.getKey(), (String) entry.getValue()));
            }
        }
    }

    public void clear() {
        this.customHeaders.clear();
    }

    public void add(CustomHeader ch) {
        this.customHeaders.add(ch);
        this.fireTableRowsInserted(this.customHeaders.size() - 1, this.customHeaders.size() - 1);
    }

    public void update(int tableIndex, CustomHeader ch) {
        this.customHeaders.set(tableIndex, ch);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.customHeaders.size()) {
            this.customHeaders.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }

    public static class CustomHeader {
        private String name;
        private String value;

        public CustomHeader() {}

        public CustomHeader(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
