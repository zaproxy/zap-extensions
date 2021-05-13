/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class HttpFuzzerErrorsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = -7564323068526325209L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.errors.table.header.taskId"),
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.errors.table.header.source"),
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.errors.table.header.message")
    };

    private List<FuzzerError> errors;

    public HttpFuzzerErrorsTableModel() {
        errors = new ArrayList<>();
    }

    public void addFuzzerError(final long taskId, final String source, final String message) {
        EventQueue.invokeLater(
                () -> {
                    int row = errors.size();
                    errors.add(new FuzzerError(taskId, source, message));
                    fireTableRowsInserted(row, row);
                });
    }

    @Override
    public int getRowCount() {
        return errors.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        FuzzerError error = errors.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return Long.valueOf(error.getTaskId());
            case 1:
                return error.getSource();
            case 2:
                return error.getMessage();
        }
        return "";
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Long.class;
        }
        return String.class;
    }

    private static class FuzzerError {

        private final long taskId;
        private final String source;
        private final String message;

        public FuzzerError(long taskId, String source, String message) {
            this.taskId = taskId;
            this.source = source;
            this.message = message;
        }

        public long getTaskId() {
            return taskId;
        }

        public String getSource() {
            return source;
        }

        public String getMessage() {
            return message;
        }
    }
}
