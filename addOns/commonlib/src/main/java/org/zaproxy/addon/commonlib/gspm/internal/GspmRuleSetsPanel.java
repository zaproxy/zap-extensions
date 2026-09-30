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

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Supplier;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * Panel for the GSPM dialog's "Rule Sets" tree node: a flat, ordered table of every {@link
 * GspmRuleSet} in the policy, with Add/Edit/Delete/Move Up/Move Down.
 *
 * <p>List order is match-precedence order (last match wins — see {@link
 * GspmPolicy#getEffectiveThreshold}/{@link GspmPolicy#getEffectiveStrength}), so this table never
 * uses a row sorter: row order must always mirror {@link GspmPolicy#getRuleSets()}. Rule sets
 * created implicitly by the phase/category tree nodes (via {@link
 * GspmPolicy#findOrCreateCategoryRuleSet}) appear here too, sharing the same backing list, so edits
 * made in either place are immediately visible in the other.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
class GspmRuleSetsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final int[] COL_WIDTHS = {160, 220, 90, 90};

    private final GspmPolicy policy;
    private final Supplier<List<GspmRule>> rulesSupplier;
    private final GspmRuleSetTableModel tableModel;
    private final JTable table;
    private JButton editButton;
    private JButton deleteButton;
    private JButton moveUpButton;
    private JButton moveDownButton;

    GspmRuleSetsPanel(
            String displayName, GspmPolicy policy, Supplier<List<GspmRule>> rulesSupplier) {
        this.policy = policy;
        this.rulesSupplier = rulesSupplier;
        setName(displayName);
        setLayout(new BorderLayout(0, 2));

        add(
                new ZapHtmlLabel(
                        "<html>"
                                + Constant.messages.getString("commonlib.gspm.dialog.rulesets.note")
                                + "</html>"),
                BorderLayout.NORTH);

        tableModel = new GspmRuleSetTableModel();
        tableModel.setRuleSets(policy.getRuleSets());
        table = buildTable();
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildButtonsPanel(), BorderLayout.EAST);
        updateButtonState();
    }

    @Override
    public void initParam(Object obj) {
        // no-op
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        // no-op — editing is in-place
    }

    @Override
    public void onShow() {
        refresh();
    }

    @Override
    public void onHide() {
        // Commit any in-progress cell edit before switching away, for the same reason as
        // GspmDialog.GspmRulesPanel#onHide().
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    private void refresh() {
        tableModel.setRuleSets(policy.getRuleSets());
        updateButtonState();
    }

    private JTable buildTable() {
        JTable t = new JTable(tableModel);
        t.setRowHeight(DisplayUtils.getScaledSize(18));
        t.setIntercellSpacing(new java.awt.Dimension(1, 1));
        // No row sorter: row order is match-precedence order and must mirror the policy's list.
        t.setAutoCreateRowSorter(false);
        t.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        for (int i = 0; i < COL_WIDTHS.length; i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(COL_WIDTHS[i]);
        }

        JComboBox<String> thresholdEditor = new JComboBox<>();
        for (AlertThreshold th : AlertThreshold.values()) {
            if (th != AlertThreshold.DEFAULT) {
                thresholdEditor.addItem(
                        Constant.messages.getString(
                                "ascan.policy.level." + th.name().toLowerCase(Locale.ROOT)));
            }
        }
        t.getColumnModel()
                .getColumn(GspmRuleSetTableModel.COL_THRESHOLD)
                .setCellEditor(new DefaultCellEditor(thresholdEditor));

        JComboBox<String> strengthEditor = new JComboBox<>();
        for (AttackStrength s : AttackStrength.values()) {
            if (s != AttackStrength.DEFAULT) {
                strengthEditor.addItem(
                        Constant.messages.getString(
                                "ascan.policy.level." + s.name().toLowerCase(Locale.ROOT)));
            }
        }
        t.getColumnModel()
                .getColumn(GspmRuleSetTableModel.COL_STRENGTH)
                .setCellEditor(new DefaultCellEditor(strengthEditor));

        t.getSelectionModel().addListSelectionListener(e -> updateButtonState());
        t.addMouseListener(
                new MouseAdapter() {
                    @Override
                    public void mousePressed(MouseEvent e) {
                        if (e.getClickCount() >= 2 && table.rowAtPoint(e.getPoint()) >= 0) {
                            editSelected();
                        }
                    }
                });
        return t;
    }

    /**
     * Builds a vertical column of buttons to the right of the table, matching the layout {@link
     * org.zaproxy.zap.view.StandardFieldsDialog#addTableField(String, JTable, List)} uses elsewhere
     * in ZAP (e.g. {@link GspmPolicyManagerDialog}'s policy list) — buttons stacked at the top,
     * trailing spacer pushing them up, rather than a row along the bottom.
     */
    private JPanel buildButtonsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        int row = 0;

        JButton addButton =
                new JButton(
                        Constant.messages.getString("commonlib.gspm.dialog.rulesets.button.add"));
        addButton.addActionListener(e -> addRuleSet());
        panel.add(addButton, buttonConstraints(row++));

        editButton =
                new JButton(
                        Constant.messages.getString("commonlib.gspm.dialog.rulesets.button.edit"));
        editButton.addActionListener(e -> editSelected());
        panel.add(editButton, buttonConstraints(row++));

        deleteButton =
                new JButton(
                        Constant.messages.getString(
                                "commonlib.gspm.dialog.rulesets.button.delete"));
        deleteButton.addActionListener(e -> deleteSelected());
        panel.add(deleteButton, buttonConstraints(row++));

        moveUpButton =
                new JButton(
                        Constant.messages.getString(
                                "commonlib.gspm.dialog.rulesets.button.moveup"));
        moveUpButton.addActionListener(e -> moveSelected(-1));
        panel.add(moveUpButton, buttonConstraints(row++));

        moveDownButton =
                new JButton(
                        Constant.messages.getString(
                                "commonlib.gspm.dialog.rulesets.button.movedown"));
        moveDownButton.addActionListener(e -> moveSelected(1));
        panel.add(moveDownButton, buttonConstraints(row++));

        // Spacer so the buttons stay anchored to the top instead of spreading out vertically.
        GridBagConstraints spacer = buttonConstraints(row);
        spacer.weighty = 1.0;
        panel.add(new JLabel(), spacer);

        return panel;
    }

    private static GridBagConstraints buttonConstraints(int row) {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(2, 2, 2, 2);
        return gbc;
    }

    private void updateButtonState() {
        int row = table.getSelectedRow();
        boolean hasSelection = row >= 0;
        editButton.setEnabled(hasSelection);
        deleteButton.setEnabled(hasSelection);
        moveUpButton.setEnabled(hasSelection && row > 0);
        moveDownButton.setEnabled(hasSelection && row < tableModel.getRowCount() - 1);
    }

    private void addRuleSet() {
        GspmRuleSetDialog dialog =
                new GspmRuleSetDialog(
                        SwingUtilities.getWindowAncestor(this),
                        policy,
                        rulesSupplier.get(),
                        availableTags(),
                        availableCategoryOptions());
        dialog.setVisible(true);
        refresh();
        int lastRow = tableModel.getRowCount() - 1;
        if (lastRow >= 0) {
            table.setRowSelectionInterval(lastRow, lastRow);
        }
    }

    private void editSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        GspmRuleSet rs = tableModel.getRuleSet(row);
        GspmRuleSetDialog dialog =
                new GspmRuleSetDialog(
                        SwingUtilities.getWindowAncestor(this),
                        policy,
                        rs,
                        rulesSupplier.get(),
                        availableTags(),
                        availableCategoryOptions());
        dialog.setVisible(true);
        refresh();
        if (row < tableModel.getRowCount()) {
            table.setRowSelectionInterval(row, row);
        }
    }

    /** Returns every distinct alert tag carried by any rule currently known to the policy. */
    private List<String> availableTags() {
        TreeSet<String> tags = new TreeSet<>();
        for (GspmRule rule : rulesSupplier.get()) {
            Map<String, String> alertTags = rule.getAlertTags();
            if (alertTags != null) {
                tags.addAll(alertTags.keySet());
            }
        }
        return new ArrayList<>(tags);
    }

    /**
     * Returns the catch-all plus every phase and category currently known to the policy's rules,
     * keyed by the exact string {@link GspmPolicy#findOrCreateCategoryRuleSet(String)} expects, in
     * the same order they appear in the GSPM dialog's tree: "All rules (catch-all)" first, then
     * each phase (e.g. "Active") followed by its categories (e.g. "Active / Client Browser"). Used
     * to populate {@link GspmRuleSetDialog}'s category pulldown.
     *
     * <p>Phases are emitted in {@link GspmPhase#values()} declaration order rather than whatever
     * order they happen to appear in {@code rulesSupplier}'s list, so this can't disagree with the
     * tree even if the underlying rule collection's iteration order isn't stable across calls;
     * tools/categories within a phase still follow first-seen order, same as {@code
     * GspmDialog#buildPanels()}, which this otherwise replicates rather than shares — keep the two
     * in sync if that method's grouping ever changes.
     */
    private LinkedHashMap<String, String> availableCategoryOptions() {
        LinkedHashMap<GspmPhase, LinkedHashMap<String, LinkedHashMap<String, String>>> byPhase =
                new LinkedHashMap<>();
        for (GspmRule rule : rulesSupplier.get()) {
            GspmCategory cat = rule.getCategories().get(0);
            byPhase.computeIfAbsent(rule.getPhase(), p -> new LinkedHashMap<>())
                    .computeIfAbsent(rule.getTool(), k -> new LinkedHashMap<>())
                    .putIfAbsent(cat.id(), cat.displayName());
        }

        LinkedHashMap<String, String> options = new LinkedHashMap<>();
        options.put(
                GspmRuleSet.ALL_CATEGORY,
                Constant.messages.getString("commonlib.gspm.ruleset.dialog.category.all"));
        for (GspmPhase phase : GspmPhase.values()) {
            LinkedHashMap<String, LinkedHashMap<String, String>> tools = byPhase.get(phase);
            if (tools == null) {
                continue;
            }
            String phaseDisplay = phase.getDisplayName();
            options.put(GspmRuleSet.PHASE_PREFIX + phase.name(), phaseDisplay);

            for (var toolEntry : tools.entrySet()) {
                String toolCatKey = GspmRuleSet.ALL_CATEGORY + "." + toolEntry.getKey();
                for (var catEntry : toolEntry.getValue().entrySet()) {
                    options.put(
                            toolCatKey + "." + catEntry.getKey(),
                            phaseDisplay + " / " + catEntry.getValue());
                }
            }
        }
        return options;
    }

    private void deleteSelected() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        GspmRuleSet rs = tableModel.getRuleSet(row);
        int confirm =
                JOptionPane.showConfirmDialog(
                        this,
                        MessageFormat.format(
                                Constant.messages.getString(
                                        "commonlib.gspm.dialog.rulesets.delete.message"),
                                GspmRuleSetTableModel.displayName(rs)),
                        Constant.messages.getString("commonlib.gspm.dialog.rulesets.delete.title"),
                        JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            policy.removeRuleSet(rs);
            refresh();
        }
    }

    private void moveSelected(int delta) {
        int row = table.getSelectedRow();
        if (row < 0) {
            return;
        }
        GspmRuleSet rs = tableModel.getRuleSet(row);
        policy.moveRuleSet(rs, delta);
        refresh();
        int newRow = row + delta;
        if (newRow >= 0 && newRow < tableModel.getRowCount()) {
            table.setRowSelectionInterval(newRow, newRow);
        }
    }
}
