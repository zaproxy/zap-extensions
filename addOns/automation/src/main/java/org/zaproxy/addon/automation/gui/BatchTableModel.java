/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.PlanBatch;
import org.zaproxy.addon.automation.PlanBatch.Status;

/** The table model of the plans listed in the batch panel. */
@SuppressWarnings("serial")
class BatchTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMNS = {
        "automation.batch.table.plan", "automation.batch.table.status"
    };

    private static class Row {
        private final File file;
        private Status status = Status.NOT_RUN;
        private List<String> errors = List.of();

        private Row(File file) {
            this.file = file;
        }
    }

    private final List<Row> rows = new ArrayList<>();

    /** Sets the plans listed, which are all not run. */
    void setFiles(List<File> files) {
        rows.clear();
        files.forEach(f -> rows.add(new Row(f)));
        fireTableDataChanged();
    }

    File getFile(int row) {
        return rows.get(row).file;
    }

    List<File> getFiles() {
        return rows.stream().map(r -> r.file).toList();
    }

    Status getStatus(int row) {
        return rows.get(row).status;
    }

    List<String> getErrors(int row) {
        return rows.get(row).errors;
    }

    /** Sets the plans given back to not run, as they are about to be run. */
    void reset(List<File> files) {
        for (int i = 0; i < rows.size(); i++) {
            Row row = rows.get(i);
            if (files.contains(row.file)) {
                row.status = Status.NOT_RUN;
                row.errors = List.of();
                fireTableRowsUpdated(i, i);
            }
        }
    }

    /** Updates the row of the plan with its state. */
    void update(PlanBatch.Entry entry) {
        for (int i = 0; i < rows.size(); i++) {
            Row row = rows.get(i);
            if (row.file.equals(entry.getFile())) {
                row.status = entry.getStatus();
                row.errors = entry.getErrors();
                fireTableRowsUpdated(i, i);
                return;
            }
        }
    }

    /** Gets the first row that did not pass, or -1. */
    int getFirstProblemRow() {
        for (int i = 0; i < rows.size(); i++) {
            Status status = rows.get(i).status;
            if (status == Status.FAIL || status == Status.LOAD_ERROR || status == Status.STOPPED) {
                return i;
            }
        }
        return -1;
    }

    static String getStatusText(Status status) {
        return Constant.messages.getString(
                "automation.batch.status." + status.name().replace("_", "").toLowerCase());
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return Constant.messages.getString(COLUMNS[column]);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        Row row = rows.get(rowIndex);
        return columnIndex == 0 ? row.file.getName() : getStatusText(row.status);
    }
}
