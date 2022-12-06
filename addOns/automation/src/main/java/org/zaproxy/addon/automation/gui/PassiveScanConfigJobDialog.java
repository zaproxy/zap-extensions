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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class PassiveScanConfigJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params", "automation.dialog.pscanconfig.tab.rules"
    };

    private static final String TITLE = "automation.dialog.pscanconfig.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String MAX_ALERTS_PER_RULE_PARAM =
            "automation.dialog.pscanconfig.maxalertsperrule";
    private static final String SCAN_ONLY_IN_SCOPE_PARAM =
            "automation.dialog.pscanconfig.scanonlyinscope";
    private static final String MAX_BODY_SIZE_PARAM = "automation.dialog.pscanconfig.maxbodysize";
    private static final String ENABLE_TAGS_PARAM = "automation.dialog.pscanconfig.enabletags";

    private PassiveScanConfigJob job;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable rulesTable = null;
    private PscanRulesTableModel rulesModel = null;

    public PassiveScanConfigJobDialog(PassiveScanConfigJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        this.addNumberField(
                0,
                MAX_ALERTS_PER_RULE_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxAlertsPerRule()));
        this.addNumberField(
                0,
                MAX_BODY_SIZE_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxBodySizeInBytesToScan()));
        this.addCheckBoxField(
                0,
                SCAN_ONLY_IN_SCOPE_PARAM,
                JobUtils.unBox(this.job.getParameters().getScanOnlyInScope()));
        this.addCheckBoxField(
                0, ENABLE_TAGS_PARAM, JobUtils.unBox(this.job.getParameters().getEnableTags()));
        this.addPadding(0);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(1, getRulesTable(), buttons);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setMaxAlertsPerRule(this.getIntValue(MAX_ALERTS_PER_RULE_PARAM));
        this.job.getParameters().setScanOnlyInScope(this.getBoolValue(SCAN_ONLY_IN_SCOPE_PARAM));
        this.job.getParameters().setMaxBodySizeInBytesToScan(this.getIntValue(MAX_BODY_SIZE_PARAM));
        this.job.getParameters().setEnableTags(this.getBoolValue(ENABLE_TAGS_PARAM));
        this.job.getData().setRules(this.getRulesModel().getRules());
        this.job.resetAndSetChanged();
    }

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
                        AddPscanRuleDialog dialog = new AddPscanRuleDialog(getRulesModel());
                        dialog.setVisible(true);
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            modifyButton.setEnabled(false);
            this.modifyButton.addActionListener(
                    e -> {
                        int row = getRulesTable().getSelectedRow();
                        AddPscanRuleDialog dialog =
                                new AddPscanRuleDialog(
                                        getRulesModel(), getRulesModel().getRules().get(row), row);
                        dialog.setVisible(true);
                    });
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final PassiveScanConfigJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.pscanconfig.remove.confirm"))) {
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
                    .setPreferredWidth(DisplayUtils.getScaledSize(270));
            rulesTable
                    .getColumnModel()
                    .getColumn(2)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
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
                                AddPscanRuleDialog dialog =
                                        new AddPscanRuleDialog(
                                                getRulesModel(),
                                                getRulesModel().getRules().get(row),
                                                row);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return rulesTable;
    }

    private PscanRulesTableModel getRulesModel() {
        if (rulesModel == null) {
            rulesModel = new PscanRulesTableModel();
            rulesModel.setRules(job.getData().getRules());
        }
        return rulesModel;
    }
}
