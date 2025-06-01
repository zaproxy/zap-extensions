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
package org.zaproxy.zap.extension.replacer.automation;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.replacer.automation.ReplacerJob.RuleData;

@SuppressWarnings("serial")
public class ReplacerTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("replacer.automation.dialog.table.header.desc"),
        Constant.messages.getString("replacer.automation.dialog.table.header.match"),
        Constant.messages.getString("replacer.automation.dialog.table.header.replacement")
    };

    private List<RuleData> replacers = new ArrayList<>();

    public ReplacerTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return replacers.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        RuleData replacer = this.replacers.get(row);
        if (replacer != null) {
            switch (col) {
                case 0:
                    return replacer.getDescription();
                case 1:
                    return replacer.getMatchString();
                case 2:
                    return replacer.getReplacementString();
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

    public List<RuleData> getReplacers() {
        return replacers;
    }

    public void setReplacers(List<RuleData> replacers) {
        if (replacers == null) {
            this.replacers = new ArrayList<>();
        } else {
            this.replacers = replacers;
        }
    }

    public void clear() {
        this.replacers.clear();
    }

    public void add(RuleData replacer) {
        this.replacers.add(replacer);
        this.fireTableRowsInserted(this.replacers.size() - 1, this.replacers.size() - 1);
    }

    public void update(int tableIndex, RuleData replacer) {
        this.replacers.set(tableIndex, replacer);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.replacers.size()) {
            this.replacers.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
