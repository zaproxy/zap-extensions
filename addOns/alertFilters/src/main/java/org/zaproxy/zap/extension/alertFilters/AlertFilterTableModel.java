/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

/** A table model for holding a set of AlertFilter, for a {@link Context}. */
@SuppressWarnings("serial")
public class AlertFilterTableModel extends AbstractMultipleOptionsTableModel<AlertFilter> {

    /** The Constant defining the table column names. */
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("alertFilters.table.header.enabled"),
        Constant.messages.getString("alertFilters.table.header.alertid"),
        Constant.messages.getString("alertFilters.table.header.url"),
        Constant.messages.getString("alertFilters.table.header.newalert")
    };

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 4463944219657112162L;

    /** The alert filters. */
    private List<AlertFilter> alertFilters = new ArrayList<>();

    /**
     * Instantiates a new alert filters table model. An internal copy of the provided list is
     * stored.
     *
     * @param alertFilters the alert filters
     */
    public AlertFilterTableModel(List<AlertFilter> alertFilters) {
        this.alertFilters = new ArrayList<>(alertFilters);
    }

    /** Instantiates a new alert filter table model. */
    public AlertFilterTableModel() {
        this.alertFilters = new ArrayList<>();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public int getRowCount() {
        return alertFilters.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        AlertFilter af = alertFilters.get(rowIndex);
        if (af == null) {
            return null;
        }
        switch (columnIndex) {
            case 0:
                return af.isEnabled();
            case 1:
                return ExtensionAlertFilters.getRuleNameForId(af.getRuleId());
            case 2:
                return af.getUrl();
            case 3:
                return af.getNewRiskName();
            default:
                return null;
        }
    }

    @Override
    public List<AlertFilter> getElements() {
        return alertFilters;
    }

    /**
     * Gets the internal list of alertFilters managed by this model.
     *
     * @return the alertFilters
     */
    public List<AlertFilter> getAlertFilters() {
        return alertFilters;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        // Just the enable/disable
        return (columnIndex == 0);
    }

    /**
     * Sets a new list of alertFilters for this model. An internal copy of the provided list is
     * stored.
     *
     * @param alertFilters the new alertFilters
     */
    public void setAlertFilters(List<AlertFilter> alertFilters) {
        this.alertFilters = new ArrayList<>(alertFilters);
        this.fireTableDataChanged();
    }

    /** Removes all the alertFilters for this model. */
    public void removeAllAlertFilters() {
        this.alertFilters = new ArrayList<>();
        this.fireTableDataChanged();
    }

    /**
     * Adds a new alert filter to this model
     *
     * @param af the alert filter being added
     */
    public void addAlertFilter(AlertFilter af) {
        this.alertFilters.add(af);
        this.fireTableRowsInserted(this.alertFilters.size() - 1, this.alertFilters.size() - 1);
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return Boolean.class;
            case 1:
                return String.class;
            case 2:
                return String.class;
            case 3:
                return String.class;
            default:
                return null;
        }
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0) {
            if (aValue instanceof Boolean) {
                alertFilters.get(rowIndex).setEnabled(((Boolean) aValue).booleanValue());
                fireTableCellUpdated(rowIndex, columnIndex);
            }
        }
    }
}
