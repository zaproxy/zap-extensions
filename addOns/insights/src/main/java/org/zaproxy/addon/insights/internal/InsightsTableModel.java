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
package org.zaproxy.addon.insights.internal;

import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;

@SuppressWarnings("serial")
public class InsightsTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("insights.table.header.level"),
        Constant.messages.getString("insights.table.header.reason"),
        Constant.messages.getString("insights.table.header.stat"),
        Constant.messages.getString("insights.table.header.site"),
        Constant.messages.getString("insights.table.header.desc"),
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<Insight> insights;

    public InsightsTableModel() {}

    public void setInsights(List<Insight> insights) {
        this.insights = insights;
        this.fireTableDataChanged();
    }

    public void insightChanged(int index, boolean added) {
        if (index >= 0) {
            if (added) {
                this.fireTableRowsInserted(index, index);
            } else {
                this.fireTableRowsUpdated(index, index);
            }
        } else {
            this.fireTableDataChanged();
        }
    }

    public Insight getRow(int index) {
        return insights.get(index);
    }

    @Override
    public int getRowCount() {
        if (insights != null) {
            return insights.size();
        }
        return 0;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return switch (column) {
            case 0 -> Insight.Level.class;
            case 1 -> Insight.Reason.class;
            case 2 -> String.class;
            case 3 -> String.class;
            case 4 -> String.class;
            default -> Object.class;
        };
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (insights != null) {
            Insight ins = insights.get(rowIndex);
            return switch (columnIndex) {
                case 0 -> ins.getLevel();
                case 1 -> ins.getReason();
                case 2 -> ins.getStatisticStr();
                case 3 -> ins.getSite();
                case 4 -> ins.getDescription();
                default -> null;
            };
        }
        return null;
    }
}
