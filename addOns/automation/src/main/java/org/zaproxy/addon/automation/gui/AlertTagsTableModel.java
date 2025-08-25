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
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;

@SuppressWarnings("serial")
public class AlertTagsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private final String columnName;

    private List<Pattern> alertTagPatterns = new ArrayList<>();

    public AlertTagsTableModel(String columnName) {
        super();
        this.columnName = Objects.requireNonNull(columnName, "Column name must not be null");
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public int getRowCount() {
        return alertTagPatterns.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        Pattern alertTagPattern = this.alertTagPatterns.get(row);
        if (alertTagPattern != null) {
            return alertTagPattern.pattern();
        }
        return null;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (aValue instanceof String alertTagPatternStr) {
            try {
                Pattern alertTagPattern = Pattern.compile(alertTagPatternStr);
                this.alertTagPatterns.set(rowIndex, alertTagPattern);
                this.fireTableCellUpdated(rowIndex, columnIndex);
            } catch (PatternSyntaxException e) {
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        "automation.dialog.ascanpolicyalerttags.error.badregex",
                                        alertTagPatternStr));
            }
        } else {
            throw new IllegalArgumentException(
                    "Expected a String value for alert tag pattern, but got: " + aValue);
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return true;
    }

    @Override
    public String getColumnName(int col) {
        if (col != 0) {
            throw new IndexOutOfBoundsException("Column index out of bounds: " + col);
        }
        return columnName;
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    public List<Pattern> getAlertTagPatterns() {
        return alertTagPatterns;
    }

    public void setAlertTagPatterns(List<Pattern> alertTagPatterns) {
        this.alertTagPatterns = Objects.requireNonNullElseGet(alertTagPatterns, ArrayList::new);
    }

    public void clear() {
        this.alertTagPatterns.clear();
    }

    public void add(Pattern alertTagPattern) {
        this.alertTagPatterns.add(alertTagPattern);
        this.fireTableRowsInserted(
                this.alertTagPatterns.size() - 1, this.alertTagPatterns.size() - 1);
    }

    public void update(int tableIndex, Pattern alertTagPattern) {
        this.alertTagPatterns.set(tableIndex, alertTagPattern);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.alertTagPatterns.size()) {
            this.alertTagPatterns.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
