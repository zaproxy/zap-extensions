/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import org.zaproxy.addon.automation.jobs.ApiJob;

public class ApiParameterTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.api.table.header.name"),
        Constant.messages.getString("automation.dialog.api.table.header.value")
    };

    private List<ApiJob.ApiParameter> apiParameters = new ArrayList<>();

    public ApiParameterTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return apiParameters.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        ApiJob.ApiParameter apiParameter = this.apiParameters.get(row);
        if (apiParameter != null) {
            switch (col) {
                case 0:
                    return apiParameter.getName();
                case 1:
                    return apiParameter.getValue();
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

    public List<ApiJob.ApiParameter> getApiParameters() {
        return apiParameters;
    }

    public void setApiParameters(List<ApiJob.ApiParameter> apiParameters) {
        if (apiParameters == null) {
            this.apiParameters = new ArrayList<>();
        } else {
            this.apiParameters = apiParameters;
        }
    }

    public void clear() {
        this.apiParameters.clear();
    }

    public void add(ApiJob.ApiParameter apiParameter) {
        this.apiParameters.add(apiParameter);
        this.fireTableRowsInserted(this.apiParameters.size() - 1, this.apiParameters.size() - 1);
    }

    public void update(int tableIndex, ApiJob.ApiParameter apiParameter) {
        this.apiParameters.set(tableIndex, apiParameter);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.apiParameters.size()) {
            this.apiParameters.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }
}
