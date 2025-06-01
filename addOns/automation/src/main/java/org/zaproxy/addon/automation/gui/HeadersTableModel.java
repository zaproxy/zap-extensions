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
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.RequestorJob;

@SuppressWarnings("serial")
public class HeadersTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.header.table.header.name"),
        Constant.messages.getString("automation.dialog.header.table.header.value")
    };

    private List<RequestorJob.Request.Header> headers = new ArrayList<>();

    public HeadersTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return headers.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        RequestorJob.Request.Header header = this.headers.get(row);
        if (header != null) {
            switch (col) {
                case 0:
                    return header.getName();
                case 1:
                    return header.getValue();
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

    public List<RequestorJob.Request.Header> getHeaders() {
        return headers;
    }

    public void setHeaders(List<RequestorJob.Request.Header> headers) {
        this.clear();
        if (headers != null) {
            for (RequestorJob.Request.Header entry : headers) {
                this.headers.add(
                        new RequestorJob.Request.Header(entry.getName(), entry.getValue()));
            }
        }
    }

    public void clear() {
        this.headers.clear();
    }

    public void add(RequestorJob.Request.Header header) {
        this.headers.add(header);
        this.fireTableRowsInserted(this.headers.size() - 1, this.headers.size() - 1);
    }

    public void update(int tableIndex, RequestorJob.Request.Header header) {
        this.headers.set(tableIndex, header);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.headers.size()) {
            this.headers.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
