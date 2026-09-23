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

import com.fasterxml.jackson.core.type.TypeReference;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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
import javax.swing.JTextField;
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
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.ZapLabel;

/**
 * Dialog for the Global Scan Policy Manager.
 *
 * <p>Extends {@link AbstractParamDialog}. The left-hand tree is provided by the base class; each
 * tree node corresponds to a {@link GspmRulesPanel}. The root node shows all rules and supports
 * policy-wide defaults; phase nodes (the fixed, tool-independent "Active"/"Passive" top level, see
 * {@link GspmPhase}) show every rule under that phase, regardless of which tool contributed it, and
 * support setting a phase-wide default via {@link GspmRuleSet#PHASE_PREFIX}-scoped rule sets (see
 * {@link GspmRuleSet#matches(GspmRule)}); category nodes (owned by exactly one tool, but a tool may
 * contribute several sibling categories under the same phase) show rules for that specific category
 * and support setting policy defaults scoped to it, same as before. More specific rule sets win
 * under last-match semantics regardless of which node created them.
 *
 * @since 1.45.0
 */
@SuppressWarnings("serial")
public class GspmDialog extends AbstractParamDialog {

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = LogManager.getLogger(GspmDialog.class);

    private static final int[] COL_WIDTHS = {280, 100, 100, 80};
    private static final int DIALOG_WIDTH = 900;
    private static final int DIALOG_HEIGHT = 600;

    private final GspmRegistry registry;
    private final GspmPolicy policy;
    private final String savedRuleSetsSnapshot;
    private boolean confirmed = false;

    private final List<GspmRulesPanel> panels = new ArrayList<>();
    private JTextField policyNameField;

    public GspmDialog(Window owner, GspmRegistry registry) {
        this(owner, registry, null);
    }

    public GspmDialog(Window owner, GspmRegistry registry, GspmPolicy policy) {
        super(
                owner,
                true,
                policy != null
                        ? Constant.messages.getString(
                                "commonlib.gspm.dialog.policy.title", policy.getName())
                        : Constant.messages.getString("commonlib.gspm.dialog.title"),
                Constant.messages.getString("commonlib.gspm.dialog.tree.root"));
        this.registry = registry;
        this.policy = policy;
        this.savedRuleSetsSnapshot = snapshotRuleSets(policy);

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
        String newName = policyNameField.getText().trim();
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
            String newName = policyNameField.getText().trim();
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
        buildPanels();
    }

    private void buildPanels() {
        List<GspmRule> effectiveRules = getEffectiveRules();

        // Top-level "All Rules" panel
        GspmRulesPanel allPanel =
                new GspmRulesPanel(
                        Constant.messages.getString("commonlib.gspm.dialog.tree.root"),
                        GspmRuleSet.ALL_CATEGORY,
                        effectiveRules);
        addParamPanel(null, allPanel, false);
        panels.add(allPanel);

        // Group rules by phase (fixed, tool-independent top level, e.g. "Active"/"Passive"), then
        // by tool, then by category id → display name. Each rule self-reports its phase (see
        // GspmRule#getPhase()); several tools may share a phase, each still contributing its own
        // category siblings.
        LinkedHashMap<GspmPhase, LinkedHashMap<String, LinkedHashMap<String, String>>> byPhase =
                new LinkedHashMap<>();
        for (GspmRule rule : effectiveRules) {
            GspmCategory cat = rule.getCategories().get(0);
            byPhase.computeIfAbsent(rule.getPhase(), p -> new LinkedHashMap<>())
                    .computeIfAbsent(rule.getTool(), k -> new LinkedHashMap<>())
                    .putIfAbsent(cat.id(), cat.displayName());
        }

        for (var phaseEntry : byPhase.entrySet()) {
            GspmPhase phase = phaseEntry.getKey();
            String phaseDisplay = phase.getDisplayName();
            String phaseKey = GspmRuleSet.PHASE_PREFIX + phase.name();

            List<GspmRule> phaseRules =
                    effectiveRules.stream()
                            .filter(r -> r.getPhase() == phase)
                            .collect(Collectors.toList());

            // Phase nodes are an aggregate view across every tool sharing that phase, and also
            // support setting policy defaults for the whole phase — see
            // GspmRuleSet#PHASE_PREFIX/#matches(GspmRule).
            GspmRulesPanel phasePanel = new GspmRulesPanel(phaseDisplay, phaseKey, phaseRules);
            addParamPanel(new String[0], phasePanel, true);
            panels.add(phasePanel);

            for (var toolEntry : phaseEntry.getValue().entrySet()) {
                String toolKey = toolEntry.getKey();
                String toolCatKey = GspmRuleSet.ALL_CATEGORY + "." + toolKey;

                for (var catEntry : toolEntry.getValue().entrySet()) {
                    String catDisplay = catEntry.getValue();
                    String catFullKey = toolCatKey + "." + catEntry.getKey();

                    List<GspmRule> catRules =
                            effectiveRules.stream()
                                    .filter(
                                            r -> {
                                                String rk = GspmRuleSet.ruleCategoryKey(r);
                                                return rk.equals(catFullKey)
                                                        || rk.startsWith(catFullKey + ".");
                                            })
                                    .collect(Collectors.toList());

                    GspmRulesPanel catPanel = new GspmRulesPanel(catDisplay, catFullKey, catRules);
                    addParamPanel(new String[] {phaseDisplay}, catPanel, true);
                    panels.add(catPanel);
                }
            }
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
        if (policy != null && savedRuleSetsSnapshot != null) {
            try {
                List<GspmRuleSet> original =
                        GspmPolicy.YAML_MAPPER.readValue(
                                savedRuleSetsSnapshot, new TypeReference<List<GspmRuleSet>>() {});
                policy.setRuleSets(original);
            } catch (Exception e) {
                LOGGER.error("Failed to revert GSPM policy changes on cancel", e);
            }
        }
    }

    private static String snapshotRuleSets(GspmPolicy policy) {
        if (policy == null) {
            return null;
        }
        try {
            return GspmPolicy.YAML_MAPPER.writeValueAsString(policy.getRuleSets());
        } catch (Exception e) {
            LOGGER.error("Failed to snapshot GSPM policy ruleSets", e);
            return null;
        }
    }

    private class GspmRulesPanel extends AbstractParamPanel {

        private static final long serialVersionUID = 1L;

        private final String categoryKey;
        private GspmRuleTableModel tableModel;
        private JComboBox<String> policyThresholdCombo;
        private JComboBox<String> policyStrengthCombo;
        private JLabel policyStrengthLabel;
        private JLabel customValuesLabel;
        private boolean updatingCombos = false;

        GspmRulesPanel(String displayName, String categoryKey, List<GspmRule> initialRules) {
            this.categoryKey = categoryKey;
            setName(displayName);
            setLayout(new BorderLayout(0, 2));
            tableModel = new GspmRuleTableModel();
            tableModel.setRules(initialRules);
            if (policy != null) {
                JPanel north = new JPanel(new BorderLayout());
                if (GspmRuleSet.ALL_CATEGORY.equals(categoryKey)) {
                    north.add(buildPolicyInfoPanel(), BorderLayout.NORTH);
                }
                north.add(buildPolicyDefaultsPanel(), BorderLayout.SOUTH);
                add(north, BorderLayout.NORTH);
                tableModel.addTableModelListener(e -> updateCombos());
            }
            add(new JScrollPane(buildTable()), BorderLayout.CENTER);
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
            // Refresh rules from registry so edits in other panels are reflected
            List<GspmRule> fresh = getEffectiveRules();
            List<GspmRule> filtered;
            if (GspmRuleSet.ALL_CATEGORY.equals(categoryKey)) {
                filtered = fresh;
            } else if (categoryKey.startsWith(GspmRuleSet.PHASE_PREFIX)) {
                GspmPhase phase =
                        GspmPhase.valueOf(categoryKey.substring(GspmRuleSet.PHASE_PREFIX.length()));
                filtered =
                        fresh.stream()
                                .filter(r -> r.getPhase() == phase)
                                .collect(Collectors.toList());
            } else {
                filtered =
                        fresh.stream()
                                .filter(
                                        r -> {
                                            String rk = GspmRuleSet.ruleCategoryKey(r);
                                            return rk.equals(categoryKey)
                                                    || rk.startsWith(categoryKey + ".");
                                        })
                                .collect(Collectors.toList());
            }
            tableModel.setRules(filtered);
            updateCombos();
        }

        private JPanel buildPolicyInfoPanel() {
            JPanel panel = new JPanel(new GridBagLayout());
            panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.insets = new Insets(2, 4, 2, 4);
            gbc.anchor = GridBagConstraints.WEST;

            gbc.gridx = 0;
            gbc.gridy = 0;
            JLabel nameLabel =
                    new JLabel(Constant.messages.getString("commonlib.gspm.dialog.policy.name"));
            panel.add(nameLabel, gbc);

            policyNameField = new JTextField(policy.getName(), 30);
            policyNameField.setEditable(
                    !GspmRegistry.getDefaultPolicyName().equals(policy.getName()));
            nameLabel.setLabelFor(policyNameField);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(policyNameField, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.weightx = 0.0;
            gbc.fill = GridBagConstraints.NONE;
            JLabel fileNameLabel =
                    new JLabel(Constant.messages.getString("commonlib.gspm.dialog.policy.file"));
            panel.add(fileNameLabel, gbc);

            ZapLabel fileLabel = new ZapLabel(policyFilePath());
            fileNameLabel.setLabelFor(fileLabel);
            gbc.gridx = 1;
            gbc.weightx = 1.0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(fileLabel, gbc);

            return panel;
        }

        private String policyFilePath() {
            File f = policy.getFile();
            if (f == null) {
                f =
                        new File(
                                Constant.getPoliciesDir(),
                                policy.getFileName() + GspmPolicy.EXTENSION);
            }
            return f.getAbsolutePath();
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
                k = parentKey(k);
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
                k = parentKey(k);
            }
            return AttackStrength.MEDIUM;
        }

        private static String parentKey(String key) {
            if (key == null || GspmRuleSet.ALL_CATEGORY.equals(key)) {
                return null;
            }
            int dot = key.lastIndexOf('.');
            return dot > 0 ? key.substring(0, dot) : GspmRuleSet.ALL_CATEGORY;
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
