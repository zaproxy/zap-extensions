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

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamContainerPanel;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;

/**
 * A tree of the rules of one phase of a policy, with the same nodes and controls as the phase in
 * {@link GspmDialog}, and the policy's Rule Sets (e.g. to set the rules with a tag). The phase node
 * is the root. Used for the Policy tab of the active scan dialog, see {@link GspmScanPolicyEditor}.
 */
@SuppressWarnings("serial")
class GspmPolicyPanel extends AbstractParamContainerPanel {

    private static final long serialVersionUID = 1L;

    private final transient GspmRegistry registry;
    private final GspmPhase phase;
    private final transient GspmPolicy policy;

    /**
     * Creates the tree for the given phase and policy.
     *
     * <p>The tree is not rebuilt when the policy changes, a new panel should be created instead, as
     * the panel of the root node can not be removed.
     *
     * @param registry the registry.
     * @param phase the phase shown.
     * @param policy the policy, edited in place.
     * @param changeListener notified when the policy might have been changed in the panel.
     */
    GspmPolicyPanel(
            GspmRegistry registry, GspmPhase phase, GspmPolicy policy, Runnable changeListener) {
        super(phase.getDisplayName());
        this.registry = registry;
        this.phase = phase;
        this.policy = policy;

        List<GspmRulesPanel> panels = new ArrayList<>();
        List<GspmRule> rules = getRules();
        for (GspmCategoryTree.Node node :
                GspmCategoryTree.build(rules, registry::getToolDisplayName)) {
            List<GspmRule> nodeRules =
                    rules.stream().filter(r -> GspmCategoryTree.belongsTo(r, node.key())).toList();
            GspmRulesPanel panel =
                    new GspmRulesPanel(
                            registry,
                            policy,
                            this::getRules,
                            node.displayName(),
                            node.key(),
                            nodeRules);
            panel.setChangeListener(changeListener);
            if (node.path().isEmpty()) {
                // The phase node, the root.
                addParamPanel(null, panel, false);
            } else {
                // The path starts with the phase, which is the root.
                List<String> parent = node.path().subList(1, node.path().size());
                addParamPanel(parent.toArray(new String[0]), panel, true);
            }
            panels.add(panel);
        }

        if (policy != null && !panels.isEmpty()) {
            // After the category nodes, not sorted among them. It shows all the rule sets of the
            // policy, as their order matters, but offers only the tags and categories of this
            // phase's rules for new ones.
            GspmRuleSetsPanel ruleSetsPanel =
                    new GspmRuleSetsPanel(
                            Constant.messages.getString("commonlib.gspm.dialog.tree.rulesets"),
                            policy,
                            this::getRules,
                            registry::getToolDisplayName);
            ruleSetsPanel.setChangeListener(changeListener);
            addParamPanel(new String[0], ruleSetsPanel, false);
        }

        expandRoot();
        for (GspmRulesPanel p : panels) {
            expandParamPanelNode(p.getName());
        }
        showDialog(true);
    }

    private List<GspmRule> getRules() {
        if (policy == null) {
            return List.of();
        }
        return registry.getAllRulesForPolicy(policy).stream()
                .filter(r -> r.getPhase() == phase)
                .toList();
    }
}
