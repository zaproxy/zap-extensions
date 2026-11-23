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
package org.zaproxy.zap.extension.zest.dialogs;

import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

/** A table model for the CSS selectors of the shadow hosts. */
@SuppressWarnings("serial")
public class ShadowPathTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String COLUMN_NAME =
            Constant.messages.getString("zest.shadowPath.table.selector");

    private List<String> values = new ArrayList<>();

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public int getRowCount() {
        return values.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        return values.get(row);
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAME;
    }

    @Override
    public Class<?> getColumnClass(int c) {
        return String.class;
    }

    public List<String> getValues() {
        return values;
    }

    public void setValues(List<String> values) {
        this.values = new ArrayList<>(values);
        fireTableDataChanged();
    }

    public void add(String selector) {
        values.add(selector);
        fireTableRowsInserted(values.size() - 1, values.size() - 1);
    }

    public void replace(int index, String selector) {
        if (index >= 0 && index < values.size()) {
            values.set(index, selector);
            fireTableRowsUpdated(index, index);
        }
    }

    public void remove(int index) {
        if (index >= 0 && index < values.size()) {
            values.remove(index);
            fireTableRowsDeleted(index, index);
        }
    }
}
