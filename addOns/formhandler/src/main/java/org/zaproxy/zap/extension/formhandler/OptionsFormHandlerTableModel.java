/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

@SuppressWarnings("serial")
public class OptionsFormHandlerTableModel
        extends AbstractMultipleOptionsTableModel<FormHandlerParamField> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("formhandler.options.table.column.enabled"),
        Constant.messages.getString("formhandler.options.table.column.field"),
        Constant.messages.getString("formhandler.options.table.column.value")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<FormHandlerParamField> fields = new ArrayList<>(0);

    public OptionsFormHandlerTableModel() {
        super();
    }

    @Override
    public List<FormHandlerParamField> getElements() {
        return fields;
    }

    /** @param fields The fields to set. */
    public void setFields(List<FormHandlerParamField> fields) {
        this.fields = new ArrayList<>(fields.size());

        for (FormHandlerParamField field : fields) {
            this.fields.add(new FormHandlerParamField(field));
        }

        fireTableDataChanged();
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Class<?> getColumnClass(int c) {
        if (c == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public int getRowCount() {
        return fields.size();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return (columnIndex == 0);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Boolean.valueOf(getElement(rowIndex).isEnabled());
            case 1:
                return getElement(rowIndex).getName();
            case 2:
                return getElement(rowIndex).getValue();
        }
        return null;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0) {
            if (aValue instanceof Boolean) {
                fields.get(rowIndex).setEnabled(((Boolean) aValue).booleanValue());
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
