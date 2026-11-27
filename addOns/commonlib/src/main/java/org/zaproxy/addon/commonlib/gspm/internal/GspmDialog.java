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
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.view.AbstractParamDialog;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;

/**
 * Dialog for the Global Scan Policy Manager.
 *
 * <p>Extends {@link AbstractParamDialog}. The left-hand tree is provided by the base class. When
 * editing an actual policy, the root node is a {@link GspmSummaryPanel} ("Summary" — policy
 * name/directory, an explanatory note, and a read-only enabled-rules report), with "All Rules" and
 * "Rule Sets" ({@link GspmRuleSetsPanel}) as its children; in the tool-wide "browse all rules" mode
 * (no policy), the root is "All Rules" directly, as there's nothing to summarize. Each other tree
 * node corresponds to a {@link GspmRulesPanel}: phase nodes (the fixed, tool-independent
 * "Active"/"Passive" top level, see {@link GspmPhase}) show every rule under that phase, regardless
 * of which tool contributed it, and support setting a phase-wide default via {@link
 * GspmRuleSet#PHASE_PREFIX}-scoped rule sets (see {@link GspmRuleSet#matches(GspmRule)}); category
 * nodes, nested as deep as the rules' own category hierarchies (shared by every tool using the same
 * category ids, see {@link GspmCategoryTree}), show rules for that specific category and support
 * setting policy defaults scoped to it. More specific rule sets win under last-match semantics
 * regardless of which node created them.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
public class GspmDialog extends AbstractParamDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(GspmDialog.class);

    private static final int[] COL_WIDTHS = {260, 110, 80, 80, 60};
    private static final int DIALOG_WIDTH = 900;
    private static final int DIALOG_HEIGHT = 600;

    private final GspmRegistry registry;
    private final GspmPolicy policy;
    private final boolean newPolicy;
    private final List<GspmRuleSet> savedRuleSets;
    private boolean confirmed = false;

    private final List<GspmRulesPanel> panels = new ArrayList<>();
    private GspmRuleSetsPanel ruleSetsPanel;
    private GspmSummaryPanel summaryPanel;

    public GspmDialog(Window owner, GspmRegistry registry) {
        this(owner, registry, null, false);
    }

    public GspmDialog(Window owner, GspmRegistry registry, GspmPolicy policy) {
        this(owner, registry, policy, false);
    }

    /**
     * @param newPolicy {@code true} if {@code policy} was just created and has never been shown to
     *     the user under a real name — in which case the "Summary" panel's name field starts blank
     *     (rather than showing {@code policy}'s placeholder registration name) so the user is
     *     prompted to choose one, which {@link #validateParam()} then requires to be non-blank
     *     before the dialog can be saved. Ignored when {@code policy} is {@code null}.
     */
    public GspmDialog(Window owner, GspmRegistry registry, GspmPolicy policy, boolean newPolicy) {
        super(
                owner,
                true,
                policy != null
                        ? Constant.messages.getString(
                                "commonlib.gspm.dialog.policy.title", policy.getName())
                        : Constant.messages.getString("commonlib.gspm.dialog.title"),
                // The root tree node is "Summary" (with "All Rules"/"Rule Sets" as its children —
                // see buildPanels()) when editing an actual policy, since only then is there a
                // policy name/directory/enabled-rules report to summarize; in the tool-wide
                // "browse all rules" mode (no policy), the root stays plain "All Rules", as before.
                policy != null
                        ? Constant.messages.getString("commonlib.gspm.dialog.tree.summary")
                        : Constant.messages.getString("commonlib.gspm.dialog.tree.allrules"));
        this.registry = registry;
        this.policy = policy;
        this.newPolicy = policy != null && newPolicy;
        this.savedRuleSets = copyRuleSets(policy);

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(
                new WindowAdapter() {
                    @Override
                    public void windowClosing(WindowEvent e) {
                        onCancel();
                        dispose();
                    }
                });

        setPreferredSize(new Dimension(DIALOG_WIDTH, DIALOG_HEIGHT));
        buildPanels();
        pack();
        setLocationRelativeTo(getOwner());
    }

    /** Returns {@code true} if the user clicked OK to confirm changes. */
    public boolean isConfirmed() {
        return confirmed;
    }

    @Override
    public void validateParam() throws Exception {
        if (policy == null) {
            return;
        }
        String newName = summaryPanel.getPolicyNameText().trim();
        if (newName.isEmpty()) {
            throw new Exception(
                    Constant.messages.getString("commonlib.gspm.dialog.error.name.blank"));
        }
        // Only validate legality/uniqueness for a name that's actually changing: imported or
        // migrated policies may legitimately have a display name that isn't a legal file name
        // (they carry a separate, safe file name), and leaving it untouched must not block
        // saving other changes.
        if (!newName.equals(policy.getName())) {
            if (!GspmPolicy.isLegalPolicyName(newName)) {
                throw new Exception(
                        MessageFormat.format(
                                Constant.messages.getString(
                                        "commonlib.gspm.policymanager.error.badname.message"),
                                GspmPolicy.ILLEGAL_POLICY_NAME_CHRS));
            }
            GspmPolicy existing = registry.getPolicy(newName);
            if (existing != null && existing != policy) {
                throw new Exception(
                        Constant.messages.getString(
                                "commonlib.gspm.policymanager.error.exists.message"));
            }
        }
    }

    @Override
    public void saveParam() throws Exception {
        if (policy != null) {
            String newName = summaryPanel.getPolicyNameText().trim();
            if (!newName.equals(policy.getName())) {
                registry.renamePolicy(policy, newName);
            }
        }
        confirmed = true;
        super.saveParam();
    }

    @Override
    protected JButton getBtnCancel() {
        JButton btn = super.getBtnCancel();
        btn.addActionListener(e -> onCancel());
        return btn;
    }

    /**
     * Reloads all rules from the registry and rebuilds the panel/tree hierarchy. Call this after
     * rules have been registered or unregistered.
     */
    public void refresh() {
        for (GspmRulesPanel p : panels) {
            removeParamPanel(p);
        }
        panels.clear();
        if (ruleSetsPanel != null) {
            removeParamPanel(ruleSetsPanel);
            ruleSetsPanel = null;
        }
        if (summaryPanel != null) {
            removeParamPanel(summaryPanel);
            summaryPanel = null;
        }
        buildPanels();
    }

    private void buildPanels() {
        List<GspmRule> effectiveRules = getEffectiveRules();

        String allRulesName = Constant.messages.getString("commonlib.gspm.dialog.tree.allrules");
        GspmRulesPanel allPanel =
                new GspmRulesPanel(allRulesName, GspmRuleSet.ALL_CATEGORY, effectiveRules);

        // Phase (and, in turn, category) nodes always nest under "All Rules" — when there's a
        // policy, that's ["All Rules"] (itself a child of the "Summary" root, see below);
        // without one, "All Rules" is the root's own content, so an empty path (root) already
        // means the same place.
        String[] phaseParent = policy != null ? new String[] {allRulesName} : new String[0];

        if (policy != null) {
            // "Summary" is the root's own content — the policy name/directory/enabled-rules
            // report that used to live in the "All Rules" panel — with "All Rules" and "Rule
            // Sets" as its children instead of top-level siblings of a plain "All Rules" root.
            // Only meaningful when editing an actual policy (not the tool-wide "browse all
            // rules" mode, which has no policy name/directory/rule sets to summarize).
            summaryPanel =
                    new GspmSummaryPanel(
                            Constant.messages.getString("commonlib.gspm.dialog.tree.summary"),
                            policy,
                            this::getEffectiveRules,
                            newPolicy);
            addParamPanel(null, summaryPanel, false);

            addParamPanel(new String[0], allPanel, true);
            panels.add(allPanel);

            ruleSetsPanel =
                    new GspmRuleSetsPanel(
                            Constant.messages.getString("commonlib.gspm.dialog.tree.rulesets"),
                            policy,
                            this::getEffectiveRules,
                            registry::getToolDisplayName);
            addParamPanel(new String[0], ruleSetsPanel, true);
        } else {
            // No policy: "All Rules" is the root's own content directly, same as before this
            // tool-wide mode had no Summary/Rule Sets nodes at all.
            addParamPanel(null, allPanel, false);
            panels.add(allPanel);
        }

        // Phase nodes (fixed, tool-independent top level, e.g. "Active"/"Passive") are an
        // aggregate view across every tool sharing that phase; under them, category nodes nest as
        // deep as the rules' own category hierarchies, shared by every tool using the same
        // category ids — see GspmCategoryTree. Every node supports setting policy defaults scoped
        // to its key; see GspmRuleSet#matches(GspmRule).
        for (GspmCategoryTree.Node node :
                GspmCategoryTree.build(effectiveRules, registry::getToolDisplayName)) {
            List<GspmRule> nodeRules =
                    effectiveRules.stream()
                            .filter(r -> GspmCategoryTree.belongsTo(r, node.key()))
                            .collect(Collectors.toList());
            String[] parent = new String[phaseParent.length + node.path().size()];
            System.arraycopy(phaseParent, 0, parent, 0, phaseParent.length);
            for (int i = 0; i < node.path().size(); i++) {
                parent[phaseParent.length + i] = node.path().get(i);
            }
            GspmRulesPanel panel = new GspmRulesPanel(node.displayName(), node.key(), nodeRules);
            addParamPanel(parent, panel, true);
            panels.add(panel);
        }

        expandRoot();
        for (GspmRulesPanel p : panels) {
            expandParamPanelNode(p.getName());
        }
    }

    private List<GspmRule> getEffectiveRules() {
        return policy != null ? registry.getAllRulesForPolicy(policy) : registry.getAllRules();
    }

    private void onCancel() {
        if (policy != null && savedRuleSets != null) {
            policy.setRuleSets(savedRuleSets);
        }
    }

    private static List<GspmRuleSet> copyRuleSets(GspmPolicy policy) {
        if (policy == null) {
            return null;
        }
        try {
            return policy.copyRuleSets();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to snapshot GSPM policy ruleSets", e);
            return null;
        }
    }

    private class GspmRulesPanel extends AbstractParamPanel {

        private static final long serialVersionUID = 1L;

        private final String categoryKey;
        private GspmRuleTableModel tableModel;
        private JTable table;
        private JComboBox<String> policyThresholdCombo;
        private JComboBox<String> policyStrengthCombo;
        private JLabel policyStrengthLabel;
        private JLabel customValuesLabel;
        private boolean updatingCombos = false;

        GspmRulesPanel(String displayName, String categoryKey, List<GspmRule> initialRules) {
            this.categoryKey = categoryKey;
            setName(displayName);
            setLayout(new BorderLayout(0, 2));
            tableModel = new GspmRuleTableModel(registry::getToolDisplayName);
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
            List<GspmRule> fresh = getEffectiveRules();
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
                            Constant.messages.getString(
                                    "commonlib.gspm.dialog.policy.reset.button"));
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
         * Removes per-rule threshold/strength overrides for every rule currently shown in this
         * panel, so they fall back to (and immediately reflect) the category/catch-all default set
         * above.
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
         * Returns how many of {@code rules} have a threshold or strength that differs from the
         * given resolved defaults — i.e. how many carry their own override and would be affected by
         * {@link #resetOverrides()}.
         */
        private int customValuesCount(
                List<GspmRule> rules,
                AlertThreshold defaultThreshold,
                AttackStrength defaultStrength) {
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
            t.setIntercellSpacing(new java.awt.Dimension(1, 1));
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
}
