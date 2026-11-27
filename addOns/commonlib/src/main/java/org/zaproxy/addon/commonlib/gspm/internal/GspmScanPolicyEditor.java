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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.HierarchyEvent;
import java.util.List;
import java.util.stream.Collectors;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;
import org.zaproxy.zap.extension.ascan.ScanPolicy;

/**
 * The editor of the Policy tab of the active scan dialog, showing the Active phase of the selected
 * GSPM policy and its rule sets, with a pulldown to choose the policy. The pulldown is cleared once
 * the rules or rule sets are changed, as they no longer match a policy. The policy shown, or the
 * edited one, is restored in the next ZAP session, unless the default policy changed, see {@link
 * GspmParam}.
 *
 * <p>The edits are made to a working copy of the policy, which is never added to the registry nor
 * saved, so they apply only to the scan. The working copy also has the rules of other tools in the
 * Active phase (e.g. the PTK DAST and IAST rules), but only the active scan rules are applied to
 * the scan. Rule sets created or changed in the tab (e.g. to set the rules with a tag) are also
 * only in the working copy.
 *
 * <p>Implements the core's {@code ScanPolicyEditor}, through a proxy created by {@link
 * GspmActiveScanRegistrar}, as it's not available in the targeted ZAP version.
 */
class GspmScanPolicyEditor {

    private static final Logger LOGGER = LogManager.getLogger(GspmScanPolicyEditor.class);

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private final GspmRegistry registry;
    private final GspmParam param;
    private boolean restoreAttempted;
    private JPanel panel;
    private JPanel treePanel;
    private JComboBox<String> policyCombo;
    private boolean updatingCombo;

    private ScanPolicy scanPolicy;
    private GspmPolicy workingCopy;

    /** The rule sets of the working copy when loaded, to know if it was changed. */
    private String loadedRuleSets;

    /** The name of the policy loaded, {@code null} once the working copy was changed. */
    private String selectedPolicyName;

    /** The state of the policy and rules when loaded, to know if they were changed elsewhere. */
    private String loadedState;

    GspmScanPolicyEditor(GspmRegistry registry) {
        this(registry, null);
    }

    /**
     * @param registry the registry.
     * @param param where the state of the editor is kept between ZAP sessions, might be {@code
     *     null}.
     */
    GspmScanPolicyEditor(GspmRegistry registry, GspmParam param) {
        this.registry = registry;
        this.param = param;
    }

    JComponent getPanel() {
        if (panel == null) {
            // The dialog adds this panel once, the tree in it is replaced when the policy changes.
            panel = new JPanel(new BorderLayout());

            JPanel policyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
            JLabel label =
                    new JLabel(Constant.messages.getString("commonlib.gspm.scan.policy.label"));
            policyPanel.add(label);
            policyCombo = new JComboBox<>();
            label.setLabelFor(policyCombo);
            policyCombo.addActionListener(e -> policyComboChanged());
            policyPanel.add(policyCombo);
            panel.add(policyPanel, BorderLayout.NORTH);

            treePanel = new JPanel(new BorderLayout());
            panel.add(treePanel, BorderLayout.CENTER);

            // The dialog keeps the editor between scans, refresh when shown again in case the
            // policies or rules were changed, e.g. in the GSPM dialog.
            panel.addHierarchyListener(
                    e -> {
                        if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0
                                && panel.isShowing()) {
                            refresh();
                        }
                    });

            updatePanel();
        }
        return panel;
    }

    private void updatePanel() {
        if (panel == null) {
            return;
        }
        updatePolicyCombo();
        treePanel.removeAll();
        if (workingCopy != null) {
            treePanel.add(
                    new GspmPolicyPanel(
                            registry, GspmPhase.ACTIVE, workingCopy, this::workingCopyChanged),
                    BorderLayout.CENTER);
        }
        treePanel.revalidate();
        treePanel.repaint();
    }

    private void updatePolicyCombo() {
        if (policyCombo == null) {
            return;
        }
        updatingCombo = true;
        try {
            policyCombo.removeAllItems();
            getSortedPolicyNames().forEach(policyCombo::addItem);
            // No name selected (blank) if the working copy was changed.
            policyCombo.setSelectedItem(selectedPolicyName);
            if (selectedPolicyName == null) {
                policyCombo.setSelectedIndex(-1);
            }
        } finally {
            updatingCombo = false;
        }
    }

    /** Gets the names of the policies, in alphabetic order ignoring case. */
    List<String> getSortedPolicyNames() {
        return GspmActiveScanRegistrar.getPolicyNames(registry).stream()
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .toList();
    }

    private void policyComboChanged() {
        if (updatingCombo) {
            return;
        }
        String name = (String) policyCombo.getSelectedItem();
        if (name != null) {
            loadPolicy(name);
        }
    }

    /**
     * Sets the policy selected in the dialog, loading a working copy of it.
     *
     * <p>The first time, restores the state saved in a previous ZAP session instead, if any.
     */
    void setScanPolicy(ScanPolicy scanPolicy) {
        this.scanPolicy = scanPolicy;
        if (!restoreAttempted) {
            restoreAttempted = true;
            if (restore()) {
                return;
            }
        }
        loadPolicy(scanPolicy != null ? scanPolicy.getName() : null);
    }

    /**
     * Restores the saved state: the policy shown or, if it was edited, the edited working copy.
     *
     * @return {@code true} if restored, {@code false} if none or not possible.
     */
    private boolean restore() {
        GspmParam.State state = param != null ? param.getState() : null;
        if (state == null) {
            return false;
        }
        if (state.defaultPolicyName() != null
                && !state.defaultPolicyName().equals(registry.getCurrentPolicy())) {
            // The default policy changed since saved, which is used instead.
            return false;
        }
        if (!state.edited()) {
            if (registry.getPolicy(state.policyName()) == null) {
                return false;
            }
            // Loaded again, to have the current rules and rule sets of the policy.
            loadPolicy(state.policyName());
            return true;
        }
        try {
            GspmPolicy copy = new GspmPolicy(state.policyName());
            copy.setRuleSets(
                    JSON_MAPPER.readValue(
                            state.ruleSets(), new TypeReference<List<GspmRuleSet>>() {}));
            workingCopy = copy;
        } catch (Exception e) {
            LOGGER.warn("Failed to restore the edited policy of the active scan dialog:", e);
            return false;
        }
        loadedRuleSets = ruleSetsAsString(workingCopy);
        loadedState = null;
        selectedPolicyName = null;
        updatePanel();
        return true;
    }

    /** Saves the state of the editor, to restore it in the next ZAP session. */
    private void saveState() {
        if (param == null || workingCopy == null) {
            return;
        }
        boolean edited = selectedPolicyName == null;
        String ruleSets = null;
        if (edited) {
            try {
                ruleSets = JSON_MAPPER.writeValueAsString(workingCopy.getRuleSets());
            } catch (JsonProcessingException e) {
                LOGGER.warn("Failed to save the edited policy of the active scan dialog:", e);
                return;
            }
        }
        param.setState(
                new GspmParam.State(
                        workingCopy.getName(), edited, ruleSets, registry.getCurrentPolicy()));
    }

    /**
     * Loads a working copy of the policy with the given name, discarding any edits.
     *
     * @param name the name of the policy, might be {@code null}.
     */
    void loadPolicy(String name) {
        GspmPolicy policy = name != null ? registry.getPolicy(name) : null;
        workingCopy = policy != null ? createWorkingCopy(policy) : null;
        loadedState = policy != null ? state(policy) : null;
        loadedRuleSets = workingCopy != null ? ruleSetsAsString(workingCopy) : null;
        selectedPolicyName = workingCopy != null ? workingCopy.getName() : null;
        updatePanel();
        saveState();
    }

    /**
     * Reloads the policy shown if it, or the rules, were changed since loaded, unless the working
     * copy was changed, to keep the edits. Also updates the policies in the pulldown.
     */
    void refresh() {
        if (selectedPolicyName != null) {
            GspmPolicy policy = registry.getPolicy(selectedPolicyName);
            if (policy == null || !state(policy).equals(loadedState)) {
                // Changed or removed, show it as it is now (or nothing, if removed).
                loadPolicy(selectedPolicyName);
                return;
            }
        }
        updatePolicyCombo();
    }

    /** Gets the state of the given policy, its rule sets and the rules of the phase. */
    private String state(GspmPolicy policy) {
        String rules =
                registry.getAllRules().stream()
                        .filter(r -> r.getPhase() == GspmPhase.ACTIVE)
                        .map(r -> r.getTool() + ":" + r.getId())
                        .sorted()
                        .collect(Collectors.joining(","));
        synchronized (policy) {
            return ruleSetsAsString(policy) + rules;
        }
    }

    /**
     * Called when the working copy might have been changed in the tree, to clear the name of the
     * policy once it no longer matches the policy loaded.
     */
    void workingCopyChanged() {
        if (workingCopy == null) {
            return;
        }
        if (selectedPolicyName != null) {
            if (ruleSetsAsString(workingCopy).equals(loadedRuleSets)) {
                return;
            }
            selectedPolicyName = null;
            updatePolicyCombo();
        }
        // Edited, save the changes, unless the same as already saved.
        saveState();
    }

    /**
     * Gets the name of the policy shown, {@code null} if none or if the working copy was changed.
     */
    String getSelectedPolicyName() {
        return selectedPolicyName;
    }

    ScanPolicy getScanPolicy() {
        if (workingCopy == null) {
            return scanPolicy;
        }
        return createScanPolicy(registry, workingCopy);
    }

    private static String ruleSetsAsString(GspmPolicy policy) {
        try {
            return GspmPolicy.YAML_MAPPER.writeValueAsString(policy.getRuleSets());
        } catch (JsonProcessingException e) {
            LOGGER.warn("Failed to serialise the rule sets of the policy:", e);
            // Can't tell, assume changed.
            return "";
        }
    }

    /** Gets the working copy of the policy being edited, {@code null} if none. */
    GspmPolicy getWorkingCopy() {
        return workingCopy;
    }

    /**
     * Creates a copy of the given policy, with the same name and rule sets, not added to the
     * registry.
     */
    static GspmPolicy createWorkingCopy(GspmPolicy policy) {
        synchronized (policy) {
            GspmPolicy copy = new GspmPolicy(policy.getName());
            copy.setRuleSets(policy.copyRuleSets());
            return copy;
        }
    }

    /** Creates a scan policy with the given policy applied, as the core does for GSPM policies. */
    static ScanPolicy createScanPolicy(GspmRegistry registry, GspmPolicy policy) {
        ScanPolicy scanPolicy = new ScanPolicy();
        scanPolicy.setName(policy.getName());
        AlertThreshold threshold =
                GspmPolicyOperations.getDefaultThreshold(policy, GspmPhase.ACTIVE);
        if (threshold != null && threshold != AlertThreshold.DEFAULT) {
            scanPolicy.setDefaultThreshold(threshold);
        }
        AttackStrength strength = GspmPolicyOperations.getDefaultStrength(policy, GspmPhase.ACTIVE);
        if (strength != null && strength != AttackStrength.DEFAULT) {
            scanPolicy.setDefaultStrength(strength);
        }
        GspmActiveScanRegistrar.applyPolicy(registry, policy, scanPolicy.getPluginFactory());
        return scanPolicy;
    }
}
