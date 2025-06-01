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
package org.zaproxy.zap.extension.replacer.automation;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.replacer.ReplaceRuleAddDialog;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule;
import org.zaproxy.zap.extension.replacer.automation.ReplacerJob.RuleData;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ReplacerJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "replacer.automation.dialog.tab.params", "replacer.automation.dialog.tab.rules"
    };

    private static final String TITLE = "replacer.automation.dialog.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String DELETE_ALL_RULES_PARAM = "replacer.automation.dialog.deleteall";

    private ReplacerJob job;

    private JButton addButton;
    private JButton modifyButton;
    private JButton removeButton;

    private JTable replacerTable;
    private ReplacerTableModel replacerModel;

    public ReplacerJobDialog(ReplacerJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.job = job;

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        this.addCheckBoxField(
                0,
                DELETE_ALL_RULES_PARAM,
                JobUtils.unBox(this.job.getData().getParameters().getDeleteAllRules()));
        this.addPadding(0);

        this.addTableField(1, getReplacerTable(), buttons);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job
                .getData()
                .getParameters()
                .setDeleteAllRules(this.getBoolValue(DELETE_ALL_RULES_PARAM));
        this.job.getData().setRules(this.getReplacerModel().getReplacers());
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
                        ReplaceRuleAddDialog dialog =
                                new ReplaceRuleAddDialog(this, "replacer.add.title", null);
                        dialog.setEnableEnabled(false);
                        dialog.setVisible(true);
                        dialog.pack();
                        ReplacerParamRule rule = dialog.getRule();
                        if (rule != null) {
                            RuleData data = new RuleData();
                            ReplacerJob.replacerRuleToData(rule, data);
                            getReplacerModel().getReplacers().add(data);
                            int row = getReplacerModel().getReplacers().size() - 1;
                            getReplacerModel().fireTableRowsInserted(row, row);
                        }
                        dialog.clear();
                    });
        }
        return this.addButton;
    }

    private void modifyAction() {
        int row = getReplacerTable().getSelectedRow();
        if (row >= 0) {
            ReplaceRuleAddDialog dialog =
                    new ReplaceRuleAddDialog(this, "replacer.modify.title", null);
            dialog.setRule(
                    ReplacerJob.dataToReplacerRule(
                            getReplacerModel().getReplacers().get(row), null));
            dialog.setEnableEnabled(false);
            dialog.setVisible(true);
            dialog.pack();
            ReplacerParamRule rule = dialog.getRule();
            if (rule != null) {
                ReplacerJob.replacerRuleToData(rule, getReplacerModel().getReplacers().get(row));
                getReplacerModel().fireTableRowsUpdated(row, row);
            }
            dialog.clear();
        }
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            this.modifyButton.setEnabled(false);
            this.modifyButton.addActionListener(e -> modifyAction());
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final ReplacerJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.requestor.remove.confirm"))) {
                            getReplacerModel().remove(getReplacerTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getReplacerTable() {
        if (replacerTable == null) {
            replacerTable = new JTable();
            replacerTable.setModel(getReplacerModel());
            replacerTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(200));
            replacerTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(80));
            replacerTable
                    .getColumnModel()
                    .getColumn(2)
                    .setPreferredWidth(DisplayUtils.getScaledSize(120));
            replacerTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean enabled = getReplacerTable().getSelectedRowCount() == 1;
                                modifyButton.setEnabled(enabled);
                                removeButton.setEnabled(enabled);
                            });
            replacerTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                modifyAction();
                            }
                        }
                    });
        }
        return replacerTable;
    }

    private ReplacerTableModel getReplacerModel() {
        if (replacerModel == null) {
            replacerModel = new ReplacerTableModel();
            // Create a deep copy
            replacerModel.setReplacers(
                    job.getData().getRules().stream()
                            .map(rule -> new RuleData(rule))
                            .collect(Collectors.toList()));
        }
        return replacerModel;
    }
}
