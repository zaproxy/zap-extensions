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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class EnvVarTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.env.table.header.key"),
        Constant.messages.getString("automation.dialog.env.table.header.value")
    };

    private List<EnvVar> envVars = new ArrayList<>();

    public EnvVarTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return envVars.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        EnvVar ev = this.envVars.get(row);
        if (ev != null) {
            switch (col) {
                case 0:
                    return ev.getKey();
                case 1:
                    return ev.getValue();
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

    public List<EnvVar> getEnvVars() {
        return envVars;
    }

    public Map<String, String> getEnvVarMap() {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (EnvVar ev : envVars) {
            map.put(ev.getKey(), ev.getValue());
        }
        return map;
    }

    public void setEnvVars(Map<String, String> map) {
        this.envVars.clear();
        if (map != null) {
            for (Entry<String, String> entry : map.entrySet()) {
                this.envVars.add(new EnvVar(entry.getKey(), entry.getValue()));
            }
        }
    }

    public void clear() {
        this.envVars.clear();
    }

    public void add(EnvVar rule) {
        this.envVars.add(rule);
        this.fireTableRowsInserted(this.envVars.size() - 1, this.envVars.size() - 1);
    }

    public void update(int tableIndex, EnvVar rule) {
        this.envVars.set(tableIndex, rule);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.envVars.size()) {
            this.envVars.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }

    public static class EnvVar {
        private String key;
        private String value;

        public EnvVar() {}

        public EnvVar(String key, String value) {
            this.key = key;
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
