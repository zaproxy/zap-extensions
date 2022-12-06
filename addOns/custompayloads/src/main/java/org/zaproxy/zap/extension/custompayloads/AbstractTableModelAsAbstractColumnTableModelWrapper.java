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

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;

@SuppressWarnings("serial")
public class AbstractTableModelAsAbstractColumnTableModelWrapper<T> {

    private final AbstractTableModel abstractTableModel;
    private final ArrayList<Column<T>> columns;
    private ArrayList<T> models;

    public AbstractTableModelAsAbstractColumnTableModelWrapper(
            AbstractTableModel abstractTableModel, List<Column<T>> columns) {
        super();
        this.abstractTableModel = abstractTableModel;
        this.columns = new ArrayList<>(columns);
        this.models = new ArrayList<>();
    }

    public int getColumnCount() {
        return columns.size();
    }

    public String getColumnName(int column) {
        String nameKey = columns.get(column).getNameKey();
        return Constant.messages.getString(nameKey);
    }

    public int getRowCount() {
        return models.size();
    }

    public Object getValueAt(int row, int col) {
        if (row >= models.size() || col >= columns.size()) {
            return null;
        }

        T model = getModelAt(row);
        return columns.get(col).getValue(model);
    }

    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex >= columns.size()) {
            return null;
        }

        return getColumnAt(columnIndex).getColumnClass();
    }

    public T getModelAt(int rowIndex) {
        return models.get(rowIndex);
    }

    public List<T> getModels() {
        return models;
    }

    public Column<T> getColumnAt(int columnIndex) {
        return columns.get(columnIndex);
    }

    public void addModels(final List<T> models) {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> addModels(models));

            return;
        }

        int startIndex = this.models.size() - 1;
        for (T model : models) {
            this.models.add(model);
        }
        int lastIndex = this.models.size() - 1;
        abstractTableModel.fireTableRowsInserted(startIndex, lastIndex);
    }

    public void addModel(final T model) {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(() -> addModel(model));

            return;
        }
        models.add(model);
        int index = models.size() - 1;
        abstractTableModel.fireTableRowsInserted(index, index);
    }

    public void removeAllModels() {
        if (View.isInitialised() && !EventQueue.isDispatchThread()) {
            EventQueue.invokeLater(this::removeAllModels);
            return;
        }

        int lastIndex = Math.max(models.size() - 1, 0);
        models.clear();
        models.trimToSize();
        abstractTableModel.fireTableRowsDeleted(0, lastIndex);
    }

    public boolean isCellEditable(int row, int col) {
        T model = getModelAt(row);
        Column<T> column = getColumnAt(col);
        return column.isEditable(model);
    }

    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        T model = getModelAt(rowIndex);
        Column<T> column = getColumnAt(columnIndex);
        if (column.isEditable(model) && column instanceof EditableColumn) {
            EditableColumn<T> editColumn = (EditableColumn<T>) column;
            editColumn.setValue(model, aValue);
        }
    }
}
