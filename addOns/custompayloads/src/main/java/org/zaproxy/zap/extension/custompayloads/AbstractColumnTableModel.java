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

import java.util.List;
import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public class AbstractColumnTableModel<T> extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private final AbstractTableModelAsAbstractColumnTableModelWrapper<T> tableModel;

    public AbstractColumnTableModel(List<Column<T>> columns) {
        super();
        this.tableModel = new AbstractTableModelAsAbstractColumnTableModelWrapper<>(this, columns);
    }

    @Override
    public int getColumnCount() {
        return tableModel.getColumnCount();
    }

    @Override
    public String getColumnName(int column) {
        return tableModel.getColumnName(column);
    }

    @Override
    public int getRowCount() {
        return tableModel.getRowCount();
    }

    @Override
    public Object getValueAt(int row, int col) {
        return tableModel.getValueAt(row, col);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return tableModel.getColumnClass(columnIndex);
    }

    public T getModelAt(int rowIndex) {
        return tableModel.getModelAt(rowIndex);
    }

    public List<T> getModels() {
        return tableModel.getModels();
    }

    public Column<T> getColumnAt(int columnIndex) {
        return tableModel.getColumnAt(columnIndex);
    }

    public void addModels(final List<T> models) {
        tableModel.addModels(models);
    }

    public void addModel(final T model) {
        tableModel.addModel(model);
    }

    public void removeAllModels() {
        tableModel.removeAllModels();
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return tableModel.isCellEditable(row, col);
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        tableModel.setValueAt(aValue, rowIndex, columnIndex);
    }
}
