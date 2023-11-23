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
package org.zaproxy.addon.client.pscan;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class OptionsPassiveScan extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private JCheckBox enablePscan;
    private JTable tablePscanRules;
    private ClientPassiveScanController scanController;

    public OptionsPassiveScan(ClientPassiveScanController scanController) {
        this.scanController = scanController;
        this.setName(Constant.messages.getString("client.options.name"));

        this.setLayout(new GridBagLayout());
        int row = 0;
        row++;
        this.add(
                this.getEnablePscan(), LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 0, 5, 0)));
        row++;
        this.add(
                new JLabel(Constant.messages.getString("client.options.label.pscanrules")),
                LayoutHelper.getGBC(0, row, 2, 1.0, new Insets(0, 0, 5, 0)));
        row++;

        JScrollPane jScrollPane = new JScrollPane();
        jScrollPane.setViewportView(getTablePscanRules());
        jScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        jScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        jScrollPane.setBorder(
                BorderFactory.createEtchedBorder(javax.swing.border.EtchedBorder.RAISED));

        this.add(
                jScrollPane,
                LayoutHelper.getGBC(
                        0,
                        row,
                        2,
                        1.0,
                        1.0,
                        GridBagConstraints.BOTH,
                        GridBagConstraints.NORTHWEST,
                        new Insets(0, 0, 0, 0)));
    }

    private JCheckBox getEnablePscan() {
        if (enablePscan == null) {
            enablePscan =
                    new JCheckBox(Constant.messages.getString("client.options.label.enablepscan"));
            enablePscan.addActionListener(
                    l -> getModel().setScanningEnabled(enablePscan.isSelected()));
            enablePscan.setSelected(this.scanController.isEnabled());
        }
        return enablePscan;
    }

    private JTable getTablePscanRules() {
        if (tablePscanRules == null) {
            tablePscanRules = new JTable();
            tablePscanRules.setModel(getModel());
            tablePscanRules.setRowHeight(18);
            tablePscanRules.getColumnModel().getColumn(0).setPreferredWidth(40);
            tablePscanRules.getColumnModel().getColumn(1).setPreferredWidth(300);
        }
        return tablePscanRules;
    }

    private OptionsPscanRuleTableModel pscanRuleModel;

    private OptionsPscanRuleTableModel getModel() {
        if (pscanRuleModel == null) {
            pscanRuleModel = new OptionsPscanRuleTableModel(scanController);
        }
        return pscanRuleModel;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        ClientOptions clientParam = optionsParam.getParamSet(ClientOptions.class);
        getEnablePscan().setSelected(clientParam.isPscanEnabled());
        this.getModel().setScanningEnabled(clientParam.isPscanEnabled());
        this.getModel().setDisabledScannerIds(clientParam.getPscanRulesDisabled());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        ClientOptions clientParam = optionsParam.getParamSet(ClientOptions.class);
        this.scanController.setEnabledScanRules(getModel().getEnabledScanners());
        this.scanController.setEnabled(getEnablePscan().isSelected());
        clientParam.setPscanEnabled(getEnablePscan().isSelected());
        clientParam.setPscanRulesDisabled(getModel().getDisabledScannerIds());
    }

    @Override
    public String getHelpIndex() {
        return "addon.client.pscan";
    }

    private static class OptionsPscanRuleTableModel extends AbstractTableModel {

        private static final String[] columnNames = {
            Constant.messages.getString("client.options.label.pscantable.enabled"),
            Constant.messages.getString("client.options.label.pscantable.name")
        };

        private ClientPassiveScanController scanController;
        private boolean scanningEnabled;
        private List<ClientPassiveScanRule> enabledPscanList;

        public OptionsPscanRuleTableModel(ClientPassiveScanController scanController) {
            this.scanController = scanController;
            enabledPscanList = new ArrayList<>(scanController.getEnabledScanRules());
            scanningEnabled = scanController.isEnabled();
        }

        @Override
        public int getRowCount() {
            return scanController.getAllScanRules().size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        public List<ClientPassiveScanRule> getEnabledScanners() {
            return this.enabledPscanList;
        }

        public List<Integer> getDisabledScannerIds() {
            return this.scanController.getAllScanRules().stream()
                    .filter(Predicate.not(ClientPassiveScanRule::isEnabled))
                    .map(ClientPassiveScanRule::getId)
                    .collect(Collectors.toList());
        }

        public void setDisabledScannerIds(List<Integer> disabledScanIds) {
            enabledPscanList = new ArrayList<>();
            scanController.getEnabledScanRules().stream()
                    .forEach(
                            s -> {
                                if (disabledScanIds.stream().noneMatch(i -> (i == s.getId()))) {
                                    enabledPscanList.add(s);
                                }
                                ;
                            });
            this.fireTableDataChanged();
        }

        private ClientPassiveScanRule getScanner(int rowIndex) {
            return scanController.getAllScanRules().get(rowIndex);
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return scanningEnabled && enabledPscanList.contains(getScanner(rowIndex));
                case 1:
                    return getScanner(rowIndex).getName();
            }
            return null;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            if (columnIndex == 0) {
                return scanningEnabled;
            }
            return false;
        }

        @Override
        public void setValueAt(Object value, int row, int col) {
            if (scanningEnabled && col == 0) {
                if ((boolean) value) {
                    this.enabledPscanList.add(this.getScanner(row));
                } else {
                    this.enabledPscanList.remove(this.getScanner(row));
                }
            }
        }

        @Override
        public String getColumnName(int col) {
            return columnNames[col];
        }

        @Override
        public Class<?> getColumnClass(int c) {
            if (c == 0) {
                return Boolean.class;
            }
            return String.class;
        }

        public void setScanningEnabled(boolean scanningEnabled) {
            this.scanningEnabled = scanningEnabled;
            this.fireTableDataChanged();
        }
    }
}
