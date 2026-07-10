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
import java.util.List;
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
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.SingleColumnTableModel;
import org.zaproxy.zap.view.StandardFieldsDialog;
import org.zaproxy.zap.view.widgets.WritableFileChooser;

/**
 * Dialog for managing Global Scan Policy Manager policies.
 *
 * <p>Lists all defined policies alphabetically and provides Add, Edit, Delete, Import, and Export
 * actions. The built-in {@link GspmRegistry#getDefaultPolicyName() Default Policy} cannot be
 * deleted. Editing or adding a policy opens a {@link GspmDialog} for per-rule configuration.
 *
 * @since 1.45.0
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
                        && !GspmRegistry.getDefaultPolicyName().equals(selected)
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
        if (!GspmPolicy.isLegalPolicyName(name)) {
            JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format(
                            Constant.messages.getString(
                                    "commonlib.gspm.policymanager.error.badname.message"),
                            GspmPolicy.ILLEGAL_POLICY_NAME_CHRS),
                    Constant.messages.getString("commonlib.gspm.policymanager.add.title"),
                    JOptionPane.WARNING_MESSAGE);
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
        dialog.showDialog(true);
        if (dialog.isConfirmed()) {
            if (saveOrShowError(newPolicy)) {
                refreshModel(name);
            } else {
                // Not persisted: don't leave it registered as if it had been.
                registry.removePolicy(name);
                refreshModel(null);
            }
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
        dialog.showDialog(true);
        if (dialog.isConfirmed()) {
            saveOrShowError(p);
            refreshModel(p.getName());
        }
    }

    private void deleteSelectedPolicy() {
        String name = getSelectedName();
        if (name == null || GspmRegistry.getDefaultPolicyName().equals(name)) {
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
            if (toDelete != null && !toDelete.deleteFile()) {
                LOGGER.error("Failed to delete GSPM policy file for '{}'", name);
                JOptionPane.showMessageDialog(
                        this,
                        MessageFormat.format(
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.delete.error"),
                                name),
                        Constant.messages.getString("commonlib.gspm.policymanager.delete.title"),
                        JOptionPane.ERROR_MESSAGE);
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
                imported = GspmLegacyImporter.importPolicy(file);
            }
            if (imported == null) {
                return;
            }
            String name = imported.getName();
            GspmPolicy existing = registry.getPolicy(name);
            if (existing != null) {
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
            }
            // Persist the new policy before touching the old one, so a failure here leaves the
            // existing policy and its file untouched rather than losing it.
            imported.save();
            registry.addPolicy(imported);
            if (existing != null
                    && !sameFile(existing.getFile(), imported.getFile())
                    && !existing.deleteFile()) {
                LOGGER.warn(
                        "Failed to delete the previous GSPM policy file replaced by importing"
                                + " '{}'",
                        name);
                JOptionPane.showMessageDialog(
                        this,
                        MessageFormat.format(
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.delete.error"),
                                name),
                        Constant.messages.getString("commonlib.gspm.policymanager.button.import"),
                        JOptionPane.WARNING_MESSAGE);
            }
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

    /** Returns {@code true} if both files are non-null and resolve to the same path. */
    private static boolean sameFile(File a, File b) {
        return a != null && b != null && a.getAbsoluteFile().equals(b.getAbsoluteFile());
    }

    /**
     * Saves {@code policy}, showing an error dialog and logging if it fails, since a caller not
     * checking this would otherwise leave the user unaware that their changes were never persisted.
     *
     * @return {@code true} if the save succeeded
     */
    private boolean saveOrShowError(GspmPolicy policy) {
        try {
            policy.save();
            return true;
        } catch (IOException e) {
            LOGGER.error("Failed to save GSPM policy '{}'", policy.getName(), e);
            JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format(
                            Constant.messages.getString("commonlib.gspm.policymanager.save.error"),
                            policy.getName(),
                            e.getMessage()),
                    Constant.messages.getString("commonlib.gspm.policymanager.button.edit"),
                    JOptionPane.ERROR_MESSAGE);
            return false;
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
