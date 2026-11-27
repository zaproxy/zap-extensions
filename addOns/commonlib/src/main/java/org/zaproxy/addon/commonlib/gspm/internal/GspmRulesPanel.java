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
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.DefaultTableCellRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * A panel of the GSPM tree showing the rules of a node, with the controls to set the policy's
 * threshold and strength for the node, used by {@link GspmDialog} and {@link GspmPolicyPanel}.
 */
@SuppressWarnings("serial")
class GspmRulesPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    private static final int[] COL_WIDTHS = {260, 110, 80, 80, 60};

    private final GspmRegistry registry;
    private final GspmPolicy policy;
    private final Supplier<List<GspmRule>> rulesSupplier;

    private final String categoryKey;
    private GspmRuleTableModel tableModel;
    private JTable table;
    private JComboBox<String> policyThresholdCombo;
    private JComboBox<String> policyStrengthCombo;
    private JLabel policyStrengthLabel;
    private JLabel customValuesLabel;
    private boolean updatingCombos = false;
    private Runnable changeListener = () -> {};

    /**
     * @param registry the registry, to get the display names of the tools.
     * @param policy the policy edited, or {@code null} to show the rules without policy controls.
     * @param rulesSupplier supplies the rules to filter, with the policy applied, when shown.
     * @param displayName the name of the panel, shown in the tree.
     * @param categoryKey the category key of the node.
     * @param initialRules the rules initially shown.
     */
    GspmRulesPanel(
            GspmRegistry registry,
            GspmPolicy policy,
            Supplier<List<GspmRule>> rulesSupplier,
            String displayName,
            String categoryKey,
            List<GspmRule> initialRules) {
        this.registry = registry;
        this.policy = policy;
        this.rulesSupplier = rulesSupplier;
        this.categoryKey = categoryKey;
        setName(displayName);
        setLayout(new BorderLayout(0, 2));
        tableModel = new GspmRuleTableModel(registry::getToolDisplayName);
        tableModel.addTableModelListener(e -> changeListener.run());
        tableModel.setRules(initialRules);
        if (policy != null) {
            JPanel north = new JPanel(new BorderLayout(0, 2));
            // Only "All Rules" gets this explanatory note — it's what makes that node
            // different from its phase/category children again, per user request.
            if (GspmRuleSet.ALL_CATEGORY.equals(categoryKey)) {
                north.add(
                        new ZapHtmlLabel(
                                "<html>"
                                        + Constant.messages.getString(
                                                "commonlib.gspm.dialog.allrules.note")
                                        + "</html>"),
                        BorderLayout.NORTH);
            }
            north.add(buildPolicyDefaultsPanel(), BorderLayout.SOUTH);
            add(north, BorderLayout.NORTH);
            tableModel.addTableModelListener(e -> updateCombos());
        }
        table = buildTable();
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    /**
     * Sets the listener notified when the rules shown might have changed, e.g. after a threshold
     * was changed. It might also be notified when nothing changed.
     *
     * @param changeListener the listener, must not be {@code null}.
     */
    void setChangeListener(Runnable changeListener) {
        this.changeListener = changeListener;
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
    public void onHide() {
        // Commit any in-progress cell edit (e.g. a threshold combo the user just picked from)
        // before switching away — otherwise the edit only lands in the policy a moment after
        // this panel is hidden, so a panel showing derived state (like the Rule Sets panel)
        // can briefly show stale data on the very next tree selection.
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }
    }

    @Override
    public void onShow() {
        // Refresh rules from registry so edits in other panels are reflected
        List<GspmRule> fresh = rulesSupplier.get();
        List<GspmRule> filtered =
                fresh.stream()
                        .filter(r -> GspmCategoryTree.belongsTo(r, categoryKey))
                        .collect(Collectors.toList());
        tableModel.setRules(filtered);
        updateCombos();
    }

    private JPanel buildPolicyDefaultsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));

        JLabel thresholdLabel =
                new JLabel(
                        Constant.messages.getString(
                                "commonlib.gspm.dialog.policy.default.threshold"));
        panel.add(thresholdLabel);
        policyThresholdCombo = new JComboBox<>();
        thresholdLabel.setLabelFor(policyThresholdCombo);
        for (AlertThreshold t : AlertThreshold.values()) {
            if (t != AlertThreshold.DEFAULT) {
                policyThresholdCombo.addItem(levelLabel(t.name()));
            }
        }
        policyThresholdCombo.addActionListener(
                e -> {
                    if (updatingCombos || policy == null) {
                        return;
                    }
                    String selected = (String) policyThresholdCombo.getSelectedItem();
                    for (AlertThreshold t : AlertThreshold.values()) {
                        if (levelLabel(t.name()).equals(selected)) {
                            policy.findOrCreateCategoryRuleSet(categoryKey).setThresholdEnum(t);
                            tableModel.fireTableDataChanged();
                            break;
                        }
                    }
                });
        panel.add(policyThresholdCombo);

        policyStrengthLabel =
                new JLabel(
                        Constant.messages.getString(
                                "commonlib.gspm.dialog.policy.default.strength"));
        panel.add(policyStrengthLabel);
        policyStrengthCombo = new JComboBox<>();
        policyStrengthLabel.setLabelFor(policyStrengthCombo);
        for (AttackStrength s : AttackStrength.values()) {
            if (s != AttackStrength.DEFAULT) {
                policyStrengthCombo.addItem(levelLabel(s.name()));
            }
        }
        policyStrengthCombo.addActionListener(
                e -> {
                    if (updatingCombos || policy == null) {
                        return;
                    }
                    String selected = (String) policyStrengthCombo.getSelectedItem();
                    for (AttackStrength s : AttackStrength.values()) {
                        if (levelLabel(s.name()).equals(selected)) {
                            policy.findOrCreateCategoryRuleSet(categoryKey).setStrengthEnum(s);
                            tableModel.fireTableDataChanged();
                            break;
                        }
                    }
                });
        panel.add(policyStrengthCombo);

        JButton resetButton =
                new JButton(
                        Constant.messages.getString("commonlib.gspm.dialog.policy.reset.button"));
        resetButton.setToolTipText(
                Constant.messages.getString("commonlib.gspm.dialog.policy.reset.tooltip"));
        resetButton.addActionListener(e -> resetOverrides());
        panel.add(resetButton);

        customValuesLabel = new JLabel();
        panel.add(customValuesLabel);

        updateCombos();
        return panel;
    }

    /**
     * Removes per-rule threshold/strength overrides for every rule currently shown in this panel,
     * so they fall back to (and immediately reflect) the category/catch-all default set above.
     */
    private void resetOverrides() {
        if (policy == null) {
            return;
        }
        for (GspmRule r : tableModel.getRules()) {
            policy.clearRuleOverride(r.getId());
        }
        tableModel.fireTableDataChanged();
    }

    private void updateCombos() {
        if (policy == null || policyThresholdCombo == null || policyStrengthCombo == null) {
            return;
        }
        List<GspmRule> rules = tableModel.getRules();
        boolean hasStrength = rules.stream().anyMatch(r -> r.getAttackStrength() != null);
        policyStrengthLabel.setEnabled(hasStrength);
        policyStrengthCombo.setEnabled(hasStrength);

        updatingCombos = true;
        try {
            AlertThreshold threshold = effectiveThreshold(categoryKey);
            AttackStrength strength = effectiveStrength(categoryKey);
            policyThresholdCombo.setSelectedItem(levelLabel(threshold.name()));
            policyStrengthCombo.setSelectedItem(levelLabel(strength.name()));
            customValuesLabel.setText(
                    MessageFormat.format(
                            Constant.messages.getString(
                                    "commonlib.gspm.dialog.policy.customvalues.label"),
                            customValuesCount(rules, threshold, strength)));
        } finally {
            updatingCombos = false;
        }
    }

    /**
     * Returns how many of {@code rules} have a threshold or strength that differs from the given
     * resolved defaults — i.e. how many carry their own override and would be affected by {@link
     * #resetOverrides()}.
     */
    private int customValuesCount(
            List<GspmRule> rules, AlertThreshold defaultThreshold, AttackStrength defaultStrength) {
        int count = 0;
        for (GspmRule r : rules) {
            boolean thresholdDiffers = r.getAlertThreshold() != defaultThreshold;
            boolean strengthDiffers =
                    r.getAttackStrength() != null && r.getAttackStrength() != defaultStrength;
            if (thresholdDiffers || strengthDiffers) {
                count++;
            }
        }
        return count;
    }

    private AlertThreshold effectiveThreshold(String key) {
        String k = key;
        while (k != null) {
            Optional<AlertThreshold> t = policy.getCategoryThreshold(k);
            if (t.isPresent()) {
                return t.get();
            }
            k = GspmCategoryTree.parentKey(k);
        }
        return AlertThreshold.MEDIUM;
    }

    private AttackStrength effectiveStrength(String key) {
        String k = key;
        while (k != null) {
            Optional<AttackStrength> s = policy.getCategoryStrength(k);
            if (s.isPresent()) {
                return s.get();
            }
            k = GspmCategoryTree.parentKey(k);
        }
        return AttackStrength.MEDIUM;
    }

    private JTable buildTable() {
        JTable t = new JTable(tableModel);
        t.setRowHeight(DisplayUtils.getScaledSize(18));
        t.setIntercellSpacing(new Dimension(1, 1));
        t.setAutoCreateRowSorter(true);

        List<RowSorter.SortKey> sortKeys = new ArrayList<>(1);
        sortKeys.add(new RowSorter.SortKey(GspmRuleTableModel.COL_NAME, SortOrder.ASCENDING));
        t.getRowSorter().setSortKeys(sortKeys);

        for (int i = 0; i < COL_WIDTHS.length; i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(COL_WIDTHS[i]);
        }

        t.getColumnModel()
                .getColumn(GspmRuleTableModel.COL_STATUS)
                .setCellRenderer(
                        new DefaultTableCellRenderer() {
                            @Override
                            public Component getTableCellRendererComponent(
                                    JTable tbl,
                                    Object value,
                                    boolean isSelected,
                                    boolean hasFocus,
                                    int row,
                                    int col) {
                                Component c =
                                        super.getTableCellRendererComponent(
                                                tbl, value, isSelected, hasFocus, row, col);
                                int modelRow = tbl.convertRowIndexToModel(row);
                                String addOnName =
                                        tableModel.getRules().get(modelRow).getAddOnName();
                                ((JLabel) c).setToolTipText(addOnName);
                                return c;
                            }
                        });

        JComboBox<String> thresholdEditor = new JComboBox<>();
        for (AlertThreshold th : AlertThreshold.values()) {
            if (th != AlertThreshold.DEFAULT) {
                thresholdEditor.addItem(
                        Constant.messages.getString(
                                "ascan.policy.level." + th.name().toLowerCase(Locale.ROOT)));
            }
        }
        t.getColumnModel()
                .getColumn(GspmRuleTableModel.COL_THRESHOLD)
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
                .getColumn(GspmRuleTableModel.COL_STRENGTH)
                .setCellEditor(new DefaultCellEditor(strengthEditor));

        return t;
    }

    private static String levelLabel(String enumName) {
        return Constant.messages.getString(
                "ascan.policy.level." + enumName.toLowerCase(Locale.ROOT));
    }
}
