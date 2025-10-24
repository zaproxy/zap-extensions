/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
public class ConfigsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        // Deliberate reuse of the env strings
        Constant.messages.getString("automation.dialog.env.table.header.key"),
        Constant.messages.getString("automation.dialog.env.table.header.value")
    };

    private List<Config> configs = new ArrayList<>();

    public ConfigsTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return configs.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        Config ev = this.configs.get(row);
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

    public List<Config> getConfigs() {
        return configs;
    }

    public Map<String, String> getConfigsMap() {
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        for (Config ev : configs) {
            map.put(ev.getKey(), ev.getValue());
        }
        return map;
    }

    public void setConfigs(Map<String, String> map) {
        this.configs.clear();
        if (map != null) {
            for (Entry<String, String> entry : map.entrySet()) {
                this.configs.add(new Config(entry.getKey(), entry.getValue()));
            }
        }
    }

    public void clear() {
        this.configs.clear();
    }

    public void add(Config rule) {
        this.configs.add(rule);
        this.fireTableRowsInserted(this.configs.size() - 1, this.configs.size() - 1);
    }

    public void update(int tableIndex, Config rule) {
        this.configs.set(tableIndex, rule);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.configs.size()) {
            this.configs.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }

    public static class Config {
        private String key;
        private String value;

        public Config() {}

        public Config(String key, String value) {
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
