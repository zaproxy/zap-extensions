/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

public class ClientHistoryTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    /** The column names. */
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString(ExtensionClientIntegration.PREFIX + ".history.table.header.id"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.timestamp"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.type"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.source"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.count"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.nodename"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.nodeid"),
        Constant.messages.getString(
                ExtensionClientIntegration.PREFIX + ".history.table.header.text")
    };

    /** The Constant defining the COLUMN COUNT. */
    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private transient List<ReportedObject> history = new ArrayList<>();

    @Override
    public String getColumnName(int col) {
        return COLUMN_NAMES[col];
    }

    @Override
    public int getRowCount() {
        return history.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Integer.class;
            case 1:
                return Date.class;
            case 4:
                return Integer.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ReportedObject obj = this.history.get(rowIndex);
        if (obj instanceof ReportedElement) {
            ReportedElement node = (ReportedElement) obj;

            switch (columnIndex) {
                case 0:
                    return rowIndex;
                case 1:
                    return node.getTimestamp();
                case 2:
                    return node.getI18nType();
                case 3:
                    return node.getUrl();
                case 4:
                    return ""; // Count - not relevant here
                case 5:
                    return node.getNodeName();
                case 6:
                    return node.getId();
                case 7:
                    return node.getText();
                default:
                    return null;
            }

        } else if (obj instanceof ReportedEvent) {
            ReportedEvent ev = (ReportedEvent) obj;
            switch (columnIndex) {
                case 0:
                    return rowIndex;
                case 1:
                    return ev.getTimestamp();
                case 2:
                    return ev.getI18nType();
                case 3:
                    return ev.getUrl();
                case 4:
                    return ev.getCount();
                case 5:
                    return ev.getTagName();
                case 6:
                    return ""; // Id - not relevant here
                case 7:
                    return ""; // Text - not relevant here
                default:
                    return null;
            }
        }
        return null;
    }

    public ReportedObject getReportedObject(int rowIndex) {
        return this.history.get(rowIndex);
    }

    public synchronized void addReportedObject(ReportedObject obj) {
        history.add(obj);
        fireTableRowsInserted(history.size() - 1, history.size() - 1);
    }

    public synchronized void clear() {
        history.clear();
        fireTableDataChanged();
    }
}
