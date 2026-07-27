/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.gspm.internal;

import java.awt.Frame;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.SingleColumnTableModel;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

/**
 * Dialog for managing Global Scan Policy Manager policies.
 *
 * <p>Lists all defined policies alphabetically and provides Add, Edit, Delete, Import, and Export
 * actions. The built-in {@link GspmRegistry#DEFAULT_POLICY_NAME Default Policy} cannot be deleted.
 * Editing or adding a policy opens a {@link GspmDialog} for per-rule configuration.
 *
 * @since 1.39.0
 */
@SuppressWarnings("serial")
public class GspmPolicyManagerDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(GspmPolicyManagerDialog.class);

    private final GspmRegistry registry;

    private JButton editButton;
    private JButton deleteButton;
    private JButton exportButton;

    private JTable policyTable;
    private SingleColumnTableModel tableModel;

    public GspmPolicyManagerDialog(Frame owner, GspmRegistry registry) {
        super(
                owner,
                "commonlib.gspm.policymanager.title",
                DisplayUtils.getScaledDimension(512, 400));
        this.registry = registry;
        init();
    }

    private void init() {
        this.removeAllFields();

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getEditButton());
        buttons.add(getDeleteButton());
        buttons.add(getImportButton());
        buttons.add(getExportButton());

        this.addTableField(getPolicyTable(), buttons);
    }

    @Override
    public boolean hasCancelSaveButtons() {
        return false;
    }

    @Override
    public void save() {}

    @Override
    public String validateFields() {
        return null;
    }

    @Override
    public void setVisible(boolean visible) {
        if (visible) {
            refreshModel(null);
        }
        super.setVisible(visible);
    }

    private void refreshModel(String selectName) {
        List<String> names =
                registry.getAllPolicies().stream()
                        .map(GspmPolicy::getName)
                        .sorted(String.CASE_INSENSITIVE_ORDER)
                        .collect(Collectors.toList());
        getTableModel().setLines(names);
        if (selectName != null) {
            for (int i = 0; i < getTableModel().getRowCount(); i++) {
                if (selectName.equals(getTableModel().getValueAt(i, 0))) {
                    getPolicyTable().setRowSelectionInterval(i, i);
                    break;
                }
            }
        }
        updateButtonState();
    }

    private void updateButtonState() {
        String selected = getSelectedName();
        boolean hasSelection = selected != null;
        boolean isDeletable =
                hasSelection
                        && !GspmRegistry.DEFAULT_POLICY_NAME.equals(selected)
                        && getTableModel().getRowCount() > 1;
        getEditButton().setEnabled(hasSelection);
        getDeleteButton().setEnabled(isDeletable);
        getExportButton().setEnabled(hasSelection);
    }

    private String getSelectedName() {
        int row = getPolicyTable().getSelectedRow();
        return row >= 0 ? (String) getTableModel().getValueAt(row, 0) : null;
    }

    private SingleColumnTableModel getTableModel() {
        if (tableModel == null) {
            tableModel =
                    new SingleColumnTableModel(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.table.policy"));
            tableModel.setEditable(false);
        }
        return tableModel;
    }

    private JTable getPolicyTable() {
        if (policyTable == null) {
            policyTable = new JTable();
            policyTable.setModel(getTableModel());
            policyTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mousePressed(MouseEvent e) {
                            if (e.getClickCount() >= 2) {
                                int row = policyTable.rowAtPoint(e.getPoint());
                                if (row >= 0) {
                                    editSelectedPolicy();
                                }
                            }
                        }
                    });
            policyTable.getSelectionModel().addListSelectionListener(e -> updateButtonState());
        }
        return policyTable;
    }

    private JButton getAddButton() {
        JButton btn =
                new JButton(Constant.messages.getString("commonlib.gspm.policymanager.button.add"));
        btn.addActionListener(e -> addPolicy());
        return btn;
    }

    private JButton getEditButton() {
        if (editButton == null) {
            editButton =
                    new JButton(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.button.edit"));
            editButton.setEnabled(false);
            editButton.addActionListener(e -> editSelectedPolicy());
        }
        return editButton;
    }

    private JButton getDeleteButton() {
        if (deleteButton == null) {
            deleteButton =
                    new JButton(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.button.delete"));
            deleteButton.setEnabled(false);
            deleteButton.addActionListener(e -> deleteSelectedPolicy());
        }
        return deleteButton;
    }

    private JButton getImportButton() {
        JButton btn =
                new JButton(
                        Constant.messages.getString("commonlib.gspm.policymanager.button.import"));
        btn.addActionListener(e -> importPolicy());
        return btn;
    }

    private JButton getExportButton() {
        if (exportButton == null) {
            exportButton =
                    new JButton(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.button.export"));
            exportButton.setEnabled(false);
            exportButton.addActionListener(e -> exportSelectedPolicy());
        }
        return exportButton;
    }

    private void addPolicy() {
        String name =
                (String)
                        JOptionPane.showInputDialog(
                                this,
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.add.message"),
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.add.title"),
                                JOptionPane.PLAIN_MESSAGE,
                                null,
                                null,
                                "");
        if (name == null || name.isBlank()) {
            return;
        }
        if (registry.getPolicy(name) != null) {
            JOptionPane.showMessageDialog(
                    this,
                    Constant.messages.getString(
                            "commonlib.gspm.policymanager.error.exists.message"),
                    Constant.messages.getString("commonlib.gspm.policymanager.add.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        GspmPolicy newPolicy = new GspmPolicy(name);
        newPolicy.setDefaultThreshold(AlertThreshold.MEDIUM);
        newPolicy.setDefaultStrength(AttackStrength.MEDIUM);
        registry.addPolicy(newPolicy);
        GspmDialog dialog = new GspmDialog(this, registry, newPolicy);
        dialog.showDialog(false);
        if (dialog.isConfirmed()) {
            try {
                newPolicy.save();
            } catch (IOException e) {
                LOGGER.error("Failed to save new GSPM policy '{}'", name, e);
            }
            refreshModel(name);
        } else {
            registry.removePolicy(name);
        }
    }

    private void editSelectedPolicy() {
        String name = getSelectedName();
        if (name == null) {
            return;
        }
        GspmPolicy p = registry.getPolicy(name);
        if (p == null) {
            return;
        }
        GspmDialog dialog = new GspmDialog(this, registry, p);
        dialog.showDialog(false);
        if (dialog.isConfirmed()) {
            try {
                p.save();
            } catch (IOException e) {
                LOGGER.error("Failed to save GSPM policy '{}'", p.getName(), e);
            }
        }
    }

    private void deleteSelectedPolicy() {
        String name = getSelectedName();
        if (name == null || GspmRegistry.DEFAULT_POLICY_NAME.equals(name)) {
            return;
        }
        int confirm =
                JOptionPane.showConfirmDialog(
                        this,
                        MessageFormat.format(
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.delete.message"),
                                name),
                        Constant.messages.getString("commonlib.gspm.policymanager.delete.title"),
                        JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            GspmPolicy toDelete = registry.getPolicy(name);
            registry.removePolicy(name);
            if (toDelete != null) {
                GspmPolicy.deleteFile(toDelete.getFileName());
            }
            refreshModel(null);
        }
    }

    private void importPolicy() {
        JFileChooser chooser = new JFileChooser(new File(Constant.getZapHome()));
        FileNameExtensionFilter allFilter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("commonlib.gspm.policymanager.file.all"),
                        "policy2",
                        "policy");
        FileNameExtensionFilter policy2Filter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("commonlib.gspm.policymanager.file.policy2"),
                        "policy2");
        FileNameExtensionFilter legacyFilter =
                new FileNameExtensionFilter(
                        Constant.messages.getString("commonlib.gspm.policymanager.file.policy"),
                        "policy");
        chooser.addChoosableFileFilter(allFilter);
        chooser.addChoosableFileFilter(policy2Filter);
        chooser.addChoosableFileFilter(legacyFilter);
        chooser.setFileFilter(allFilter);
        chooser.setAcceptAllFileFilterUsed(false);

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        try {
            GspmPolicy imported;
            if (file.getName().endsWith(GspmPolicy.EXTENSION)) {
                imported = GspmPolicy.load(file);
            } else {
                Map<Integer, String> ruleNames = new HashMap<>();
                for (GspmRule rule : registry.getAllRules()) {
                    ruleNames.putIfAbsent(rule.getId(), rule.getName());
                }
                imported = GspmLegacyImporter.importPolicy(file, ruleNames);
            }
            if (imported == null) {
                return;
            }
            String name = imported.getName();
            if (registry.getPolicy(name) != null) {
                int confirm =
                        JOptionPane.showConfirmDialog(
                                this,
                                MessageFormat.format(
                                        Constant.messages.getString(
                                                "commonlib.gspm.policymanager.import.exists.message"),
                                        name),
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.import.exists.title"),
                                JOptionPane.YES_NO_OPTION);
                if (confirm != JOptionPane.YES_OPTION) {
                    return;
                }
                GspmPolicy existing = registry.getPolicy(name);
                registry.removePolicy(name);
                if (existing != null) {
                    GspmPolicy.deleteFile(existing.getFileName());
                }
            }
            registry.addPolicy(imported);
            imported.save();
            refreshModel(name);
        } catch (Exception e) {
            LOGGER.error("Failed to import GSPM policy from {}", file, e);
            JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.import.error"),
                            e.getMessage()),
                    Constant.messages.getString("commonlib.gspm.policymanager.button.import"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportSelectedPolicy() {
        String name = getSelectedName();
        if (name == null) {
            return;
        }
        GspmPolicy policy = registry.getPolicy(name);
        if (policy == null) {
            return;
        }
        WritableFileChooser chooser = new WritableFileChooser(new File(Constant.getZapHome()));
        chooser.setSelectedFile(
                new File(Constant.getZapHome(), policy.getFileName() + GspmPolicy.EXTENSION));
        chooser.setFileFilter(
                new FileNameExtensionFilter(
                        Constant.messages.getString("commonlib.gspm.policymanager.file.policy2"),
                        "policy2"));
        chooser.setAcceptAllFileFilterUsed(false);

        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        File file = chooser.getSelectedFile();
        if (file == null) {
            return;
        }
        if (!file.getName().endsWith(GspmPolicy.EXTENSION)) {
            file = new File(file.getAbsolutePath() + GspmPolicy.EXTENSION);
        }
        try {
            GspmPolicy.YAML_MAPPER.writerWithDefaultPrettyPrinter().writeValue(file, policy);
        } catch (IOException e) {
            LOGGER.error("Failed to export GSPM policy '{}'", name, e);
            JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.export.error"),
                            e.getMessage()),
                    Constant.messages.getString("commonlib.gspm.policymanager.button.export"),
                    JOptionPane.ERROR_MESSAGE);
        }
    }
}
