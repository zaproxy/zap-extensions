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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.gspm.GspmCategory;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * Builds the phase/category hierarchy shown in the GSPM dialog's tree, shared by {@link GspmDialog}
 * (the tree itself) and {@link GspmRuleSetsPanel} (the rule set dialog's category pulldown) so the
 * two can't disagree.
 *
 * <p>The hierarchy mirrors the {@link GspmRuleSet#ruleCategoryKey(GspmRule) category keys}: one
 * node per {@link GspmPhase} that has rules, in {@link GspmPhase#values()} order, keyed by {@link
 * GspmRuleSet#phaseKey(GspmPhase)} (e.g. {@code "phase.active"}), and under it one nested node per
 * level of the rules' {@link GspmRule#getCategories() categories} (e.g. {@code
 * "phase.active.browser"}, {@code "phase.active.browser.dast"}). Rules of different tools with the
 * same category ids are in the same node, e.g. ZAP's own Client Browser active scan rules and the
 * PTK DAST/IAST rules all under {@code "phase.active.browser"}.
 *
 * <p>Sibling nodes with different ids but the same display name (compared case-insensitively, as
 * the tree resolves parent nodes by name) are disambiguated by appending the tool's display name.
 */
final class GspmCategoryTree {

    private static final String LABEL_SEPARATOR = " / ";

    private GspmCategoryTree() {}

    /**
     * A node in the hierarchy.
     *
     * @param key the category key, as accepted by {@link
     *     org.zaproxy.addon.commonlib.gspm.GspmPolicy#findOrCreateCategoryRuleSet(String)}.
     * @param displayName the name shown for the node.
     * @param path the display names of the node's ancestors, starting with its phase; empty for a
     *     phase node.
     * @param phase the phase the node belongs to.
     */
    record Node(String key, String displayName, List<String> path, GspmPhase phase) {

        /** Returns the full label of the node, e.g. {@code "Active / Client Browser / DAST"}. */
        String label() {
            if (path.isEmpty()) {
                return displayName;
            }
            return String.join(LABEL_SEPARATOR, path) + LABEL_SEPARATOR + displayName;
        }
    }

    /**
     * Builds the hierarchy for the given rules, in tree pre-order (each node before its children).
     *
     * @param rules the rules.
     * @param toolDisplayNames maps a tool id to its display name, used to disambiguate siblings.
     * @return the nodes, never {@code null}.
     */
    static List<Node> build(List<GspmRule> rules, UnaryOperator<String> toolDisplayNames) {
        List<Node> nodes = new ArrayList<>();
        for (GspmPhase phase : GspmPhase.values()) {
            List<GspmRule> phaseRules = rules.stream().filter(r -> r.getPhase() == phase).toList();
            if (phaseRules.isEmpty()) {
                continue;
            }
            String phaseKey = GspmRuleSet.phaseKey(phase);
            String phaseDisplay = phase.getDisplayName();
            nodes.add(new Node(phaseKey, phaseDisplay, List.of(), phase));
            addChildren(
                    nodes, phaseRules, 0, phaseKey, List.of(phaseDisplay), phase, toolDisplayNames);
        }
        return nodes;
    }

    /**
     * Tells whether or not the given rule belongs to the node with the given key, i.e. is shown in
     * it and is affected by a category-only rule set with that key.
     */
    static boolean belongsTo(GspmRule rule, String key) {
        GspmRuleSet probe = new GspmRuleSet();
        probe.setCategory(key);
        return probe.matches(rule);
    }

    /**
     * Returns the next, less-specific key to check when resolving a node's effective
     * threshold/strength, e.g. {@code "phase.active.browser.dast"} → {@code "phase.active.browser"}
     * → {@code "phase.active"} → {@code "all"} → {@code null}. The same order in which {@link
     * org.zaproxy.addon.commonlib.gspm.GspmPolicy} ranks the rule sets.
     *
     * @param key the key, may be {@code null}.
     * @return the next key, or {@code null} once {@code "all"} has been reached.
     */
    static String parentKey(String key) {
        if (key == null || GspmRuleSet.ALL_CATEGORY.equals(key)) {
            return null;
        }
        if (GspmRuleSet.isPhaseOnlyKey(key)) {
            return GspmRuleSet.ALL_CATEGORY;
        }
        int dot = key.lastIndexOf('.');
        return dot <= 0 ? GspmRuleSet.ALL_CATEGORY : key.substring(0, dot);
    }

    private static void addChildren(
            List<Node> nodes,
            List<GspmRule> rules,
            int level,
            String parentKey,
            List<String> path,
            GspmPhase phase,
            UnaryOperator<String> toolDisplayNames) {
        // Category id → the rules in it, in first-seen order.
        Map<String, List<GspmRule>> children = new LinkedHashMap<>();
        for (GspmRule rule : rules) {
            List<GspmCategory> cats = rule.getCategories();
            if (cats.size() > level) {
                children.computeIfAbsent(cats.get(level).id(), k -> new ArrayList<>()).add(rule);
            }
        }
        Set<String> siblingNames = new HashSet<>();
        for (var child : children.entrySet()) {
            GspmRule first = child.getValue().get(0);
            String key = parentKey + "." + child.getKey();
            String name =
                    uniqueName(
                            siblingNames,
                            first.getCategories().get(level).displayName(),
                            first.getTool(),
                            toolDisplayNames);
            nodes.add(new Node(key, name, path, phase));
            addChildren(
                    nodes,
                    child.getValue(),
                    level + 1,
                    key,
                    append(path, name),
                    phase,
                    toolDisplayNames);
        }
    }

    private static String uniqueName(
            Set<String> used, String name, String tool, UnaryOperator<String> toolDisplayNames) {
        String candidate = name;
        if (used.contains(candidate.toLowerCase(Locale.ROOT))) {
            candidate =
                    Constant.messages.getString(
                            "commonlib.gspm.dialog.tree.node.tool",
                            name,
                            toolDisplayNames.apply(tool));
        }
        used.add(candidate.toLowerCase(Locale.ROOT));
        return candidate;
    }

    private static List<String> append(List<String> path, String name) {
        List<String> result = new ArrayList<>(path.size() + 1);
        result.addAll(path);
        result.add(name);
        return List.copyOf(result);
    }
}
