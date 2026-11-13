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

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * The operations to change the GSPM policies, used by the API.
 *
 * <p>The operations that are specific to a tool only affect its rules. The default threshold and
 * strength of the rules of a tool are held by the {@code all.<tool>} rule set (as done when
 * importing legacy policies), and the ones of the policy by its catch-all rule set.
 *
 * <p><strong>Note:</strong> Not part of the public API, only the operations that are {@code public}
 * are for use by other add-ons.
 */
public final class GspmPolicyOperations {

    private GspmPolicyOperations() {}

    private static String toolKey(String tool) {
        return GspmRuleSet.ALL_CATEGORY + "." + tool;
    }

    /**
     * Adds a policy.
     *
     * @param tool the tool the defaults are for, {@code null} for all the rules of the policy.
     * @param threshold the default threshold, {@code null} to use MEDIUM.
     * @param strength the default strength, {@code null} to use MEDIUM.
     * @throws IllegalStateException if a policy with the name already exists, the message being the
     *     name.
     * @throws IllegalArgumentException if the name is not legal.
     */
    public static void addPolicy(
            GspmRegistry registry,
            String name,
            String tool,
            AlertThreshold threshold,
            AttackStrength strength) {
        if (registry.getPolicy(name) != null) {
            throw new IllegalStateException(name);
        }
        if (!GspmPolicy.isLegalPolicyName(name)) {
            throw new IllegalArgumentException(name);
        }
        GspmPolicy policy = new GspmPolicy(name);
        setDefaults(
                policy,
                tool,
                threshold != null ? threshold : AlertThreshold.MEDIUM,
                strength != null ? strength : AttackStrength.MEDIUM);
        addAndSave(registry, policy);
    }

    /**
     * Updates the defaults of a policy.
     *
     * @param tool the tool the defaults are for, {@code null} for all the rules of the policy.
     * @param threshold the default threshold, {@code null} to leave unchanged.
     * @param strength the default strength, {@code null} to leave unchanged.
     */
    static void updatePolicy(
            GspmRegistry registry,
            String name,
            String tool,
            AlertThreshold threshold,
            AttackStrength strength) {
        GspmPolicy policy = getPolicy(registry, name);
        setDefaults(policy, tool, threshold, strength);
        save(policy);
    }

    private static void setDefaults(
            GspmPolicy policy, String tool, AlertThreshold threshold, AttackStrength strength) {
        if (tool == null) {
            if (threshold != null) {
                policy.setDefaultThreshold(threshold);
            }
            if (strength != null) {
                policy.setDefaultStrength(strength);
            }
            return;
        }
        GspmRuleSet ruleSet = policy.findOrCreateCategoryRuleSet(toolKey(tool));
        if (threshold != null) {
            ruleSet.setThresholdEnum(threshold);
        }
        if (strength != null) {
            ruleSet.setStrengthEnum(strength);
        }
    }

    /**
     * Gets the default threshold of the rules of the tool (or of the policy, if {@code null}), the
     * one of the policy if the tool has none.
     *
     * @return the threshold, {@code null} if not defined.
     */
    static AlertThreshold getDefaultThreshold(GspmRegistry registry, String name, String tool) {
        GspmPolicy policy = getPolicy(registry, name);
        if (tool == null) {
            return policy.getDefaultThreshold().orElse(null);
        }
        return policy.getCategoryThreshold(toolKey(tool))
                .or(policy::getDefaultThreshold)
                .orElse(null);
    }

    /**
     * Gets the default strength of the rules of the tool (or of the policy, if {@code null}), the
     * one of the policy if the tool has none.
     *
     * @return the strength, {@code null} if not defined.
     */
    static AttackStrength getDefaultStrength(GspmRegistry registry, String name, String tool) {
        GspmPolicy policy = getPolicy(registry, name);
        if (tool == null) {
            return policy.getDefaultStrength().orElse(null);
        }
        return policy.getCategoryStrength(toolKey(tool))
                .or(policy::getDefaultStrength)
                .orElse(null);
    }

    static void removePolicy(GspmRegistry registry, String name) {
        GspmPolicy policy = getPolicy(registry, name);
        checkNotBuiltIn(name);
        // The files first, as otherwise the policy would not be removed (and it would be migrated
        // again on the next start), but it would no longer be in the registry to remove it again.
        if (!policy.deleteFile()) {
            throw new UncheckedIOException(
                    new IOException("Failed to delete the policy file: " + policy.getFile()));
        }
        // The source of the migration, which might be named differently (if the name of the file
        // of the policy had to be changed), and the one named as the policy (as it would also be
        // migrated if the policy was not migrated).
        Set<File> legacyFiles = new LinkedHashSet<>();
        if (policy.getLegacyFile() != null) {
            legacyFiles.add(policy.getLegacyFile());
        }
        legacyFiles.add(new File(Constant.getPoliciesDir(), policy.getFileName() + ".policy"));
        for (File legacyFile : legacyFiles) {
            if (legacyFile.exists() && !legacyFile.delete()) {
                throw new UncheckedIOException(
                        new IOException("Failed to delete the legacy policy file: " + legacyFile));
            }
        }
        registry.removePolicy(name);
    }

    /**
     * Adds the policy to the registry and saves it, undoing the addition if it could not be saved.
     */
    private static void addAndSave(GspmRegistry registry, GspmPolicy policy) {
        registry.addPolicy(policy);
        try {
            save(policy);
        } catch (RuntimeException e) {
            registry.removePolicy(policy.getName());
            // The file might have been partially written.
            new File(Constant.getPoliciesDir(), policy.getFileName() + GspmPolicy.EXTENSION)
                    .delete();
            throw e;
        }
    }

    /**
     * Imports a legacy {@code .policy} file.
     *
     * @return the name of the imported policy.
     * @throws IOException if the file could not be read as a legacy policy.
     * @throws IllegalStateException if a policy with that name already exists, the message being
     *     the name.
     * @throws IllegalArgumentException if the name of the policy is not legal.
     */
    static String importPolicy(GspmRegistry registry, File file) throws IOException {
        GspmPolicy policy;
        try {
            policy = GspmLegacyImporter.importPolicy(file);
        } catch (Exception e) {
            throw new IOException(e.getMessage(), e);
        }
        if (policy == null) {
            throw new IOException("Failed to read the policy from " + file);
        }
        String name = policy.getName();
        if (registry.getPolicy(name) != null) {
            throw new IllegalStateException(name);
        }
        if (!GspmPolicy.isLegalPolicyName(name)) {
            throw new IllegalArgumentException(name);
        }
        addAndSave(registry, policy);
        return name;
    }

    /**
     * Sets the threshold of a rule.
     *
     * @param tool the tool the rule must be of, {@code null} for any.
     * @param threshold the threshold, a {@code null} or {@code DEFAULT} clears the override.
     */
    public static void setRuleThreshold(
            GspmRegistry registry,
            String policyName,
            String tool,
            int ruleId,
            AlertThreshold threshold) {
        GspmRule rule = getRule(registry, policyName, tool, ruleId);
        GspmPolicy policy = getPolicy(registry, policyName);
        setThreshold(policy, rule, nullIfDefault(threshold));
        save(policy);
    }

    /**
     * Sets the strength of a rule.
     *
     * @param tool the tool the rule must be of, {@code null} for any.
     * @param strength the strength, a {@code null} or {@code DEFAULT} clears the override.
     */
    public static void setRuleStrength(
            GspmRegistry registry,
            String policyName,
            String tool,
            int ruleId,
            AttackStrength strength) {
        GspmRule rule = getRule(registry, policyName, tool, ruleId);
        GspmPolicy policy = getPolicy(registry, policyName);
        setStrength(policy, rule, nullIfDefault(strength));
        save(policy);
    }

    /**
     * Sets the threshold of the rule, removing first any other override, including the ones shared
     * with other rules, as those would take precedence.
     */
    private static void setThreshold(GspmPolicy policy, GspmRule rule, AlertThreshold threshold) {
        policy.clearRuleThreshold(rule.getId());
        if (threshold != null) {
            policy.setRuleThreshold(rule.getId(), rule.getName(), threshold);
        }
    }

    private static void setStrength(GspmPolicy policy, GspmRule rule, AttackStrength strength) {
        if (rule.getAttackStrength() == null) {
            // The rule has no strength, e.g. passive rules.
            return;
        }
        policy.clearRuleStrength(rule.getId());
        if (strength != null) {
            policy.setRuleStrength(rule.getId(), rule.getName(), strength);
        }
    }

    /**
     * Enables or disables the rule, keeping its other settings. An enabled rule is not changed, so
     * it keeps its threshold.
     */
    private static void setEnabled(GspmPolicy policy, GspmRule rule, boolean enabled) {
        if (!enabled) {
            setThreshold(policy, rule, AlertThreshold.OFF);
            return;
        }
        if (rule.isEnabled()) {
            return;
        }
        policy.clearRuleThreshold(rule.getId());
        if (!rule.isEnabled()) {
            // The default is OFF, mask it with an explicit threshold.
            policy.setRuleThreshold(rule.getId(), rule.getName(), AlertThreshold.MEDIUM);
        }
    }

    /**
     * Enables or disables rules.
     *
     * @param tool the tool the rules must be of, {@code null} for any.
     */
    public static void setRulesEnabled(
            GspmRegistry registry,
            String policyName,
            String tool,
            Collection<Integer> ruleIds,
            boolean enabled) {
        GspmPolicy policy = getPolicy(registry, policyName);
        for (int id : ruleIds) {
            setEnabled(policy, getRule(registry, policyName, tool, id), enabled);
        }
        save(policy);
    }

    /** Enables or disables all the rules of the tool, leaving the other rules unchanged. */
    static void setAllRulesEnabled(
            GspmRegistry registry, String policyName, String tool, boolean enabled) {
        GspmPolicy policy = getPolicy(registry, policyName);
        for (GspmRule rule : registry.getRulesByTool(tool, policyName)) {
            setEnabled(policy, rule, enabled);
        }
        save(policy);
    }

    /**
     * Sets the threshold of all the rules of the category, overriding the per rule thresholds.
     *
     * @param categoryKey the key of the category, without the one of the tool.
     */
    static void setCategoryThreshold(
            GspmRegistry registry,
            String policyName,
            String tool,
            String categoryKey,
            AlertThreshold threshold) {
        GspmPolicy policy = getPolicy(registry, policyName);
        String key = categoryKey(tool, categoryKey);
        policy.findOrCreateCategoryRuleSet(key).setThresholdEnum(nullIfDefault(threshold));
        for (GspmRule rule : categoryRules(registry, policyName, tool, key)) {
            policy.clearRuleThreshold(rule.getId());
        }
        save(policy);
    }

    /**
     * Sets the strength of all the rules of the category, overriding the per rule strengths.
     *
     * @param categoryKey the key of the category, without the one of the tool.
     */
    static void setCategoryStrength(
            GspmRegistry registry,
            String policyName,
            String tool,
            String categoryKey,
            AttackStrength strength) {
        GspmPolicy policy = getPolicy(registry, policyName);
        String key = categoryKey(tool, categoryKey);
        policy.findOrCreateCategoryRuleSet(key).setStrengthEnum(nullIfDefault(strength));
        for (GspmRule rule : categoryRules(registry, policyName, tool, key)) {
            policy.clearRuleStrength(rule.getId());
        }
        save(policy);
    }

    /**
     * Enables the rules of the tool in the given categories, disabling all the others of the tool.
     * The rules that are already enabled are not changed, so they keep their thresholds.
     */
    static void setEnabledCategories(
            GspmRegistry registry,
            String policyName,
            String tool,
            Collection<String> categoryKeys) {
        GspmPolicy policy = getPolicy(registry, policyName);
        List<String> keys = categoryKeys.stream().map(k -> categoryKey(tool, k)).toList();
        for (GspmRule rule : registry.getRulesByTool(tool, policyName)) {
            setEnabled(policy, rule, keys.stream().anyMatch(k -> isInCategory(rule, k)));
        }
        save(policy);
    }

    /**
     * Tells whether or not the rule is in the category, that is the category of the rule is the
     * given one or one of its descendants.
     *
     * @param key the full key of the category, as returned by {@link #categoryKey(String, String)}.
     */
    static boolean isInCategory(GspmRule rule, String key) {
        String ruleKey = GspmRuleSet.ruleCategoryKey(rule);
        return ruleKey.equals(key) || ruleKey.startsWith(key + ".");
    }

    static String categoryKey(String tool, String categoryKey) {
        return toolKey(tool) + "." + categoryKey;
    }

    private static List<GspmRule> categoryRules(
            GspmRegistry registry, String policyName, String tool, String key) {
        return registry.getRulesByTool(tool, policyName).stream()
                .filter(r -> isInCategory(r, key))
                .toList();
    }

    private static GspmRule getRule(
            GspmRegistry registry, String policyName, String tool, int ruleId) {
        GspmPolicy policy = getPolicy(registry, policyName);
        List<GspmRule> rules =
                tool != null
                        ? registry.getRulesByTool(tool, policyName)
                        : registry.getAllRulesForPolicy(policy);
        return rules.stream()
                .filter(r -> r.getId() == ruleId)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown rule: " + ruleId));
    }

    /** The built-in default policy always exists, as protected by the GSPM dialog. */
    private static void checkNotBuiltIn(String name) {
        if (GspmRegistry.getDefaultPolicyName().equals(name)) {
            throw new IllegalArgumentException("The built-in policy can not be changed: " + name);
        }
    }

    private static GspmPolicy getPolicy(GspmRegistry registry, String name) {
        GspmPolicy policy = name != null ? registry.getPolicy(name) : null;
        if (policy == null) {
            throw new IllegalArgumentException("Unknown policy: " + name);
        }
        return policy;
    }

    private static AlertThreshold nullIfDefault(AlertThreshold threshold) {
        return threshold == AlertThreshold.DEFAULT ? null : threshold;
    }

    private static AttackStrength nullIfDefault(AttackStrength strength) {
        return strength == AttackStrength.DEFAULT ? null : strength;
    }

    private static void save(GspmPolicy policy) {
        try {
            policy.save();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
