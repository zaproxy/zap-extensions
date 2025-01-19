/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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

import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
/** An abstract class that provides the methods needed to add active scan policy management tabs. */
public abstract class ActiveScanPolicyDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(ActiveScanPolicyDialog.class);

    protected static final String DEFAULT_THRESHOLD_PARAM =
            "automation.dialog.ascan.defaultthreshold";
    protected static final String DEFAULT_STRENGTH_PARAM =
            "automation.dialog.ascan.defaultstrength";

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable rulesTable = null;
    private AscanRulesTableModel rulesModel = null;

    public ActiveScanPolicyDialog(String title, Dimension dimension, String[] tabLabels) {
        super(View.getSingleton().getMainFrame(), title, dimension, tabLabels);
    }

    protected JButton getAddButton() {
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
                            LOGGER.error(e1.getMessage(), e1);
                        }
                    });
        }
        return this.addButton;
    }

    protected JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            modifyButton.setEnabled(false);
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
                            LOGGER.error(e1.getMessage(), e1);
                        }
                    });
        }
        return this.modifyButton;
    }

    protected JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final ActiveScanPolicyDialog parent = this;
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

    protected JTable getRulesTable() {
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
                                boolean singleRowSelected =
                                        getRulesTable().getSelectedRowCount() == 1;
                                modifyButton.setEnabled(singleRowSelected);
                                removeButton.setEnabled(singleRowSelected);
                            });
            rulesTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = getRulesTable().getSelectedRow();
                                if (row == -1) {
                                    return;
                                }
                                try {
                                    AddAscanRuleDialog dialog =
                                            new AddAscanRuleDialog(
                                                    getRulesModel(),
                                                    getRulesModel().getRules().get(row),
                                                    row);
                                    dialog.setVisible(true);
                                } catch (ConfigurationException e1) {
                                    LOGGER.error(e1.getMessage(), e1);
                                }
                            }
                        }
                    });
        }
        return rulesTable;
    }

    protected AscanRulesTableModel getRulesModel() {
        if (rulesModel == null) {
            rulesModel = new AscanRulesTableModel();
            rulesModel.setRules(getRules());
        }
        return rulesModel;
    }

    protected abstract List<Rule> getRules();
}
