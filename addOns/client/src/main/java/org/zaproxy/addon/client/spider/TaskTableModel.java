/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class TaskTableModel extends AbstractTableModel {

    private static final long serialVersionUID = -6380136823410869457L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("client.spider.panel.table.header.id"),
        Constant.messages.getString("client.spider.panel.table.header.action"),
        Constant.messages.getString("client.spider.panel.table.header.uri"),
        Constant.messages.getString("client.spider.panel.table.header.details"),
        Constant.messages.getString("client.spider.panel.table.header.error"),
        Constant.messages.getString("client.spider.panel.table.header.status"),
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<TaskRecord> scanResults;

    public TaskTableModel() {
        scanResults = new ArrayList<>();
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public int getRowCount() {
        return scanResults.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        TaskRecord result = scanResults.get(row);
        switch (col) {
            case 0:
                return result.getId();
            case 1:
                return result.getAction();
            case 2:
                return result.getUri();
            case 3:
                return result.getDetails();
            case 4:
                return result.getError();
            case 5:
                return result.getStatus();
            default:
                return null;
        }
    }

    public void removeAllElements() {
        scanResults.clear();
        fireTableDataChanged();
    }

    public void addTask(int id, String action, String uri, String details, String status) {
        TaskRecord result = new TaskRecord(id, action, uri, details, "", status);
        scanResults.add(result);
        fireTableRowsInserted(scanResults.size() - 1, scanResults.size() - 1);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Integer.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            case 4:
                return String.class;
            case 5:
                return String.class;
        }
        return null;
    }

    @EqualsAndHashCode
    @AllArgsConstructor
    @Getter
    private static class TaskRecord {
        private int id;
        private String action;
        private String uri;
        private String details;
        @Setter private String error;
        @Setter private String status;
    }

    public void updateTaskState(int id, String newState, String error) {
        int id2 = id - 1;
        TaskRecord action = this.scanResults.get(id2);
        if (action.getId() > id) {
            while (action.getId() > id) {
                id2--;
                action = this.scanResults.get(id2);
            }
        } else if (action.getId() < id) {
            while (action.getId() < id) {
                id2++;
                action = this.scanResults.get(id2);
            }
        }
        if (action.getId() == id) {
            action.setStatus(newState);
            action.setError(error);
            this.fireTableCellUpdated(id2, 4);
        }
    }
}
