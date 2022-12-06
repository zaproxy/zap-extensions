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
import org.zaproxy.addon.automation.ContextWrapper;

@SuppressWarnings("serial")
public class ContextsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.contexts.table.header.name"),
    };

    private List<ContextWrapper> contexts = new ArrayList<>();

    public ContextsTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return contexts.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        ContextWrapper context = this.contexts.get(row);
        if (context != null) {
            return context.getData().getName();
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

    public List<ContextWrapper> getContexts() {
        return contexts;
    }

    public void setContexts(List<ContextWrapper> contexts) {
        if (contexts == null) {
            this.contexts = new ArrayList<>();
        } else {
            this.contexts = contexts;
        }
    }

    public void clear() {
        this.contexts.clear();
    }

    public void add(ContextWrapper context) {
        this.contexts.add(context);
        this.fireTableRowsInserted(this.contexts.size() - 1, this.contexts.size() - 1);
    }

    public void update(int tableIndex, ContextWrapper context) {
        this.contexts.set(tableIndex, context);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.contexts.size()) {
            this.contexts.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
