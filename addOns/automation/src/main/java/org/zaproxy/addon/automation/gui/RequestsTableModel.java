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
import org.zaproxy.addon.automation.jobs.RequestorJob;

@SuppressWarnings("serial")
public class RequestsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.requests.table.header.method"),
        Constant.messages.getString("automation.dialog.requests.table.header.url"),
        Constant.messages.getString("automation.dialog.requests.table.header.code")
    };

    private List<RequestorJob.Request> requests = new ArrayList<>();

    public RequestsTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return requests.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        RequestorJob.Request rule = this.requests.get(row);
        if (rule != null) {
            switch (col) {
                case 0:
                    return rule.getMethod();
                case 1:
                    return rule.getUrl();
                case 2:
                    return rule.getResponseCode();
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

    public List<RequestorJob.Request> getRules() {
        return requests;
    }

    public void setRules(List<RequestorJob.Request> rules) {
        if (rules == null) {
            this.requests = new ArrayList<>();
        } else {
            this.requests = rules;
        }
    }

    public void clear() {
        this.requests.clear();
    }

    public void add(RequestorJob.Request rule) {
        this.requests.add(rule);
        this.fireTableRowsInserted(this.requests.size() - 1, this.requests.size() - 1);
    }

    public void update(int tableIndex, RequestorJob.Request rule) {
        this.requests.set(tableIndex, rule);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.requests.size()) {
            this.requests.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
