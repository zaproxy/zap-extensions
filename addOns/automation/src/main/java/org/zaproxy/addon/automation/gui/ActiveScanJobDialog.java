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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ActiveScanJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params", "automation.dialog.ascan.tab.policy"
    };

    private static final String TITLE = "automation.dialog.ascan.title";
    private static final String CONTEXT_PARAM = "automation.dialog.ascan.context";

    private ActiveScanJob job;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable rulesTable = null;
    private AscanRulesTableModel rulesModel = null;

    public ActiveScanJobDialog(ActiveScanJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.job = job;

        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(0, CONTEXT_PARAM, contextNames, this.job.getParameters().getContext());

        this.addPadding(0);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(1, getRulesTable(), buttons);
    }

    @Override
    public void save() {}

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addButton.addActionListener(
                    e -> {
                        AddAscanRuleDialog dialog;
                        try {
                            dialog = new AddAscanRuleDialog(getRulesModel());
                            dialog.setVisible(true);
                        } catch (ConfigurationException e1) {
                            // TODO Auto-generated catch block
                            e1.printStackTrace();
                        }
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            this.modifyButton.addActionListener(
                    e -> {
                        int row = getRulesTable().getSelectedRow();
                        try {
                            AddAscanRuleDialog dialog =
                                    new AddAscanRuleDialog(
                                            getRulesModel(),
                                            getRulesModel().getRules().get(row),
                                            row);
                            dialog.setVisible(true);
                        } catch (ConfigurationException e1) {
                            // TODO Auto-generated catch block
                            e1.printStackTrace();
                        }
                    });
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final ActiveScanJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.ascan.remove.confirm"))) {
                            getRulesModel().remove(getRulesTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getRulesTable() {
        if (rulesTable == null) {
            rulesTable = new JTable();
            rulesTable.setModel(getRulesModel());
            rulesTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(50));
            rulesTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(170));
            rulesTable
                    .getColumnModel()
                    .getColumn(2)
                    .setPreferredWidth(DisplayUtils.getScaledSize(100));
            rulesTable
                    .getColumnModel()
                    .getColumn(3)
                    .setPreferredWidth(DisplayUtils.getScaledSize(100));
            rulesTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                if (getRulesTable().getSelectedRowCount() == 0) {
                                    modifyButton.setEnabled(false);
                                    removeButton.setEnabled(false);
                                } else if (getRulesTable().getSelectedRowCount() == 1) {
                                    modifyButton.setEnabled(true);
                                    removeButton.setEnabled(true);
                                } else {
                                    modifyButton.setEnabled(false);
                                    removeButton.setEnabled(false);
                                }
                            });
            rulesTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = getRulesTable().getSelectedRow();
                                try {
                                    AddAscanRuleDialog dialog =
                                            new AddAscanRuleDialog(
                                                    getRulesModel(),
                                                    getRulesModel().getRules().get(row),
                                                    row);
                                    dialog.setVisible(true);
                                } catch (ConfigurationException e1) {
                                    // TODO Auto-generated catch block
                                    e1.printStackTrace();
                                }
                            }
                        }
                    });
        }
        return rulesTable;
    }

    private AscanRulesTableModel getRulesModel() {
        if (rulesModel == null) {
            rulesModel = new AscanRulesTableModel();
            rulesModel.setRules(job.getData().getPolicyDefinition().getRules());
        }
        return rulesModel;
    }
}
