/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import java.awt.Dimension;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class AbstractColumnDialog<T> extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;
    private List<Column<T>> columns;
    private T model;
    private boolean saved;

    public AbstractColumnDialog(Window owner, String title, List<Column<T>> columns, T model) {
        this(owner, title, columns, model, DisplayUtils.getScaledDimension(500, 350));
    }

    public AbstractColumnDialog(
            Window owner, String title, List<Column<T>> columns, T model, Dimension dimension) {
        this(owner, title, columns, model, dimension, true);
    }

    public AbstractColumnDialog(
            Window owner,
            String title,
            List<Column<T>> columns,
            T model,
            Dimension dimension,
            boolean modal) {
        super(owner, title, dimension, modal);
        this.columns = columns;
        this.model = model;
        initFields();
    }

    private void initFields() {
        this.removeAllFields();
        for (Column<T> column : columns) {
            addField(column);
        }
    }

    private void addField(Column<T> column) {
        if (column.getColumnClass() == String.class) {
            createStringFieldForColumn(column);
        } else if (column.getColumnClass() == Boolean.class) {
            createBooleanFieldForColumn(column);
        } else if (column.getColumnClass() == Integer.class) {
            createIntFieldForColumn(column);
        }
        setFieldEnabledStateByColumnType(column);
    }

    private void createBooleanFieldForColumn(Column<T> column) {
        Boolean value = column.<Boolean>getTypedValue(model);
        this.addCheckBoxField(column.getNameKey(), value);
    }

    private void createStringFieldForColumn(Column<T> column) {
        if (column instanceof EditableSelectColumn) {
            createStringComboFieldForColumn(column);
        } else {
            createStringTextFieldForColumn(column);
        }
    }

    private void createStringTextFieldForColumn(Column<T> column) {
        String value = column.getTypedValue(model);
        this.addTextField(column.getNameKey(), value);
    }

    private void createStringComboFieldForColumn(Column<T> column) {
        EditableSelectColumn<T> selectColumn = (EditableSelectColumn<T>) column;
        String value = column.getTypedValue(model);
        ArrayList<String> selectableValues = selectColumn.getTypedSelectableValues(model);
        this.addComboField(column.getNameKey(), selectableValues, value);
    }

    private void createIntFieldForColumn(Column<T> column) {
        Integer value = column.<Integer>getTypedValue(model);
        this.addNumberField(column.getNameKey(), -1, Integer.MAX_VALUE, value);
    }

    private void setFieldEnabledStateByColumnType(Column<T> column) {
        boolean enabled = isEditable(column);
        this.getField(column.getNameKey()).setEnabled(enabled);
    }

    private boolean isEditable(Column<T> column) {
        return column.isEditable(model) && column instanceof EditableColumn;
    }

    @Override
    public void save() {
        for (Column<T> column : columns) {
            if (isEditable(column)) {
                EditableColumn<T> editableColumn = (EditableColumn<T>) column;
                Object value = getValueByColumn(editableColumn);
                editableColumn.setValue(model, value);
            }
        }
        saved = true;
    }

    @Override
    public void cancelPressed() {
        super.cancelPressed();
        saved = false;
    }

    private Object getValueByColumn(EditableColumn<T> column) {
        if (column.getColumnClass() == String.class) {
            return getStringValueByColumn(column);
        }

        if (column.getColumnClass() == Boolean.class) {
            return getBoolValueByColumn(column);
        }

        return null;
    }

    private String getStringValueByColumn(EditableColumn<T> column) {
        return this.getStringValue(column.getNameKey());
    }

    private Boolean getBoolValueByColumn(EditableColumn<T> column) {
        return getBoolValue(column.getNameKey());
    }

    @Override
    public String validateFields() {
        return null;
    }

    public boolean isSaved() {
        return saved;
    }
}
