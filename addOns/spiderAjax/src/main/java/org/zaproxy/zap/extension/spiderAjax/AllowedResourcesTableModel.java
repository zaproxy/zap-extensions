/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.spiderAjax;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

public class AllowedResourcesTableModel extends AbstractMultipleOptionsTableModel<AllowedResource> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString(
                "spiderajax.options.dialog.allowedResources.table.header.enabled"),
        Constant.messages.getString(
                "spiderajax.options.dialog.allowedResources.table.header.regex"),
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<AllowedResource> allowedResources = new ArrayList<>();

    public AllowedResourcesTableModel() {
        super();
    }

    public void setAllowedResources(List<AllowedResource> allowedResources) {
        this.allowedResources = new ArrayList<>(allowedResources.size());

        for (AllowedResource allowedResource : allowedResources) {
            this.allowedResources.add(new AllowedResource(allowedResource));
        }

        fireTableDataChanged();
    }

    @Override
    public List<AllowedResource> getElements() {
        return allowedResources;
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getRowCount() {
        return allowedResources.size();
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
            case 0:
                return getElement(rowIndex).isEnabled();
            case 1:
                return getElement(rowIndex).getPattern().pattern();
        }
        return null;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0) {
            if (aValue instanceof Boolean) {
                getElement(rowIndex).setEnabled((Boolean) aValue);
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return (columnIndex == 0);
    }
}
