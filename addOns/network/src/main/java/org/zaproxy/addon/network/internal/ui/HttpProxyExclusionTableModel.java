/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

@SuppressWarnings("serial")
public class HttpProxyExclusionTableModel
        extends AbstractMultipleOptionsTableModel<HttpProxyExclusion> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString(
                "network.ui.options.connection.httpproxy.exclusions.table.header.enabled"),
        Constant.messages.getString(
                "network.ui.options.connection.httpproxy.exclusions.table.header.host")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<HttpProxyExclusion> exclusions;

    public HttpProxyExclusionTableModel() {
        super();

        exclusions = Collections.emptyList();
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
    public int getRowCount() {
        return exclusions.size();
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        switch (columnIndex) {
            case 0:
                return getElement(rowIndex).isEnabled();
            case 1:
                return getElement(rowIndex).getHost().pattern();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && aValue instanceof Boolean) {
            exclusions.get(rowIndex).setEnabled((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    @Override
    public Class<?> getColumnClass(int c) {
        if (c == 0) {
            return Boolean.class;
        }
        return String.class;
    }

    public void setHttpProxyExclusions(List<HttpProxyExclusion> exclusions) {
        this.exclusions = new ArrayList<>(exclusions.size());
        for (HttpProxyExclusion exclusion : exclusions) {
            this.exclusions.add(new HttpProxyExclusion(exclusion));
        }
        fireTableDataChanged();
    }

    @Override
    public List<HttpProxyExclusion> getElements() {
        return exclusions;
    }
}
