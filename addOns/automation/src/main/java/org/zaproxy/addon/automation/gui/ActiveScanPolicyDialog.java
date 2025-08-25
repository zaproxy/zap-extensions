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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import lombok.AccessLevel;
import lombok.Getter;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.AlertTagRuleConfig;
import org.zaproxy.addon.automation.jobs.PolicyDefinition.Rule;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
/** An abstract class that provides the methods needed to add active scan policy management tabs. */
@Getter(value = AccessLevel.PROTECTED)
public abstract class ActiveScanPolicyDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(ActiveScanPolicyDialog.class);

    protected static final String DEFAULT_THRESHOLD_PARAM =
            "automation.dialog.ascan.defaultthreshold";
    protected static final String DEFAULT_STRENGTH_PARAM =
            "automation.dialog.ascan.defaultstrength";
    protected static final String TAG_RULE_THRESHOLD_PARAM =
            "automation.dialog.ascanpolicyalerttags.threshold";
    protected static final String TAG_RULE_STRENGTH_PARAM =
            "automation.dialog.ascanpolicyalerttags.strength";

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private JTable rulesTable = null;
    private AscanRulesTableModel rulesModel = null;

    private JTable includedTagsTable;
    private final AlertTagsTableModel includedTagsTableModel =
            new AlertTagsTableModel(
                    Constant.messages.getString(
                            "automation.dialog.ascanpolicyalerttags.includedtagpatterns"));
    private final JButton addIncludedAlertTagButton =
            createAddAlertTagButton(includedTagsTableModel);
    private final JButton removeIncludedAlertTagButton =
            createRemoveAlertTagButton(includedTagsTableModel, this::getIncludedAlertTagsTable);

    private final AlertTagsTableModel excludedTagsTableModel =
            new AlertTagsTableModel(
                    Constant.messages.getString(
                            "automation.dialog.ascanpolicyalerttags.excludedtagpatterns"));
    private JTable excludedTagsTable;
    private final JButton addExcludedAlertTagButton =
            createAddAlertTagButton(excludedTagsTableModel);
    private final JButton removeExcludedAlertTagButton =
            createRemoveAlertTagButton(excludedTagsTableModel, this::getExcludedAlertTagsTable);

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

    protected JTable getIncludedAlertTagsTable() {
        if (includedTagsTable == null) {
            includedTagsTable =
                    createAlertTagsTable(
                            getIncludedTagsTableModel(),
                            getAlertTagRule().getIncludePatterns(),
                            getRemoveIncludedAlertTagButton());
        }
        return includedTagsTable;
    }

    protected JTable getExcludedAlertTagsTable() {
        if (excludedTagsTable == null) {
            excludedTagsTable =
                    createAlertTagsTable(
                            getExcludedTagsTableModel(),
                            getAlertTagRule().getExcludePatterns(),
                            getRemoveExcludedAlertTagButton());
        }
        return excludedTagsTable;
    }

    protected AlertTagRuleConfig getAlertTagRule() {
        return null;
    }

    private JButton createAddAlertTagButton(AlertTagsTableModel model) {
        var button = new JButton(Constant.messages.getString("automation.dialog.button.add"));
        button.addActionListener(
                e -> {
                    var dialog = new AddAlertTagDialog(this, model, -1);
                    dialog.setVisible(true);
                });
        return button;
    }

    private JButton createRemoveAlertTagButton(
            AlertTagsTableModel model, Supplier<JTable> tableSupplier) {
        var button = new JButton(Constant.messages.getString("automation.dialog.button.remove"));
        button.setEnabled(false);
        button.addActionListener(e -> model.remove(tableSupplier.get().getSelectedRow()));
        return button;
    }

    private JTable createAlertTagsTable(
            AlertTagsTableModel model, List<Pattern> patterns, JButton removeButton) {
        JTable table = new JTable(model);
        model.setAlertTagPatterns(new ArrayList<>(patterns));
        table.getSelectionModel()
                .addListSelectionListener(
                        e -> {
                            boolean singleRowSelected = table.getSelectedRowCount() == 1;
                            removeButton.setEnabled(singleRowSelected);
                        });
        return table;
    }
}
