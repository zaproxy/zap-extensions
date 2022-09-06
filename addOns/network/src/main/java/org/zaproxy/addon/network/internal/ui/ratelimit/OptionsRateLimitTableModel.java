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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

@SuppressWarnings("serial")
public class OptionsRateLimitTableModel extends AbstractMultipleOptionsTableModel<RateLimitRule> {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("network.ui.ratelimit.options.table.header.enabled"),
        Constant.messages.getString("network.ui.ratelimit.options.table.header.description"),
        Constant.messages.getString("network.ui.ratelimit.options.table.header.match"),
        Constant.messages.getString("network.ui.ratelimit.options.table.header.requestspersecond"),
        Constant.messages.getString("network.ui.ratelimit.options.table.header.groupby")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<RateLimitRule> rules = new ArrayList<>(0);

    public OptionsRateLimitTableModel() {
        super();
    }

    @Override
    public List<RateLimitRule> getElements() {
        return rules;
    }

    public void setRules(List<RateLimitRule> rules) {
        this.rules = new ArrayList<>(rules.size());

        for (RateLimitRule rule : rules) {
            this.rules.add(new RateLimitRule(rule));
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
        if (c == 3) {
            return Integer.class;
        }
        return String.class;
    }

    @Override
    public int getRowCount() {
        return rules.size();
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
                return getElement(rowIndex).getDescription();
            case 2:
                return getElement(rowIndex).getMatchString();
            case 3:
                return getElement(rowIndex).getRequestsPerSecond();
            case 4:
                return getElement(rowIndex).getGroupBy().getLabel();
        }
        return null;
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 0 && aValue instanceof Boolean) {
            rules.get(rowIndex).setEnabled((Boolean) aValue);
            fireTableCellUpdated(rowIndex, columnIndex);
        }
    }

    public boolean containsRule(String description) {
        for (RateLimitRule rule : rules) {
            if (rule.getDescription().equals(description)) {
                return true;
            }
        }
        return false;
    }
}
