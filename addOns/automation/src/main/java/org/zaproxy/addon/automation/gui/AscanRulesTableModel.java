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
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJob.Rule;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;

@SuppressWarnings("serial")
public class AscanRulesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] columnNames = {
        Constant.messages.getString("automation.dialog.ascan.table.header.id"),
        Constant.messages.getString("automation.dialog.ascan.table.header.name"),
        Constant.messages.getString("automation.dialog.ascan.table.header.threshold"),
        Constant.messages.getString("automation.dialog.ascan.table.header.strength")
    };

    private List<ActiveScanJob.Rule> rules = new ArrayList<>();

    private ExtensionActiveScan extAscan;

    public AscanRulesTableModel() {
        super();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public int getRowCount() {
        return rules.size();
    }

    @Override
    public Object getValueAt(int row, int col) {
        ActiveScanJob.Rule rule = this.rules.get(row);
        if (rule != null) {
            switch (col) {
                case 0:
                    return rule.getId();
                case 1:
                    return rule.getName();
                case 2:
                    return JobUtils.thresholdToI18n(rule.getThreshold());
                case 3:
                    return JobUtils.strengthToI18n(rule.getStrength());
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

    public List<ActiveScanJob.Rule> getRules() {
        return rules;
    }

    public void setRules(List<ActiveScanJob.Rule> rules) {
        if (rules == null) {
            this.rules = new ArrayList<>();
        } else {
            this.rules = rules;
        }
    }

    public void clear() {
        this.rules.clear();
    }

    public void add(Rule rule) {
        this.rules.add(rule);
        this.fireTableRowsInserted(this.rules.size() - 1, this.rules.size() - 1);
    }

    public void update(int tableIndex, Rule rule) {
        this.rules.set(tableIndex, rule);
        this.fireTableRowsUpdated(tableIndex, tableIndex);
    }

    public void remove(int index) {
        if (index < this.rules.size()) {
            this.rules.remove(index);
            this.fireTableRowsDeleted(index, index);
        }
    }

    private ExtensionActiveScan getExtAscan() {
        if (this.extAscan == null) {
            this.extAscan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return this.extAscan;
    }

    public List<Plugin> getAllScanRules() throws ConfigurationException {
        return this.getExtAscan()
                .getPolicyManager()
                .getTemplatePolicy()
                .getPluginFactory()
                .getAllPlugin();
    }
}
