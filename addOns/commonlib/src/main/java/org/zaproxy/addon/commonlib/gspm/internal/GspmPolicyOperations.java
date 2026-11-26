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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSet;

/**
 * The operations to change the GSPM policies, used by the API.
 *
 * <p>The operations that are specific to a tool only affect its rules, and the ones specific to a
 * {@link GspmPhase} affect the rules of every tool in that phase. The default threshold and
 * strength of the rules of a phase are held by its {@link GspmRuleSet#phaseKey(GspmPhase) phase}
 * rule set (as done when importing legacy policies), and the ones of the policy by its catch-all
 * rule set.
 *
 * <p>The changes are done while holding the lock of the policy, the same one held when the policy
 * is applied to a scan, so that a scan does not see a partial change.
 *
 * <p><strong>Note:</strong> Not part of the public API, only the operations that are {@code public}
 * are for use by other add-ons.
 */
public final class GspmPolicyOperations {

    private static final String LEGACY_EXTENSION = ".policy";

    private GspmPolicyOperations() {}

    /**
     * Adds a policy.
     *
     * @param phase the phase the defaults are for, {@code null} for all the rules of the policy.
     * @param threshold the default threshold, {@code null} or {@code DEFAULT} to use MEDIUM.
     * @param strength the default strength, {@code null} or {@code DEFAULT} to use MEDIUM.
     * @throws IllegalStateException if a policy with the name already exists, the message being the
     *     name.
     * @throws IllegalArgumentException if the name is {@code null}, blank or not legal.
     */
    public static void addPolicy(
            GspmRegistry registry,
            String name,
            GspmPhase phase,
            AlertThreshold threshold,
            AttackStrength strength) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("The name of the policy must not be blank.");
        }
        if (registry.getPolicy(name) != null) {
            throw new IllegalStateException(name);
        }
        if (!GspmPolicy.isLegalPolicyName(name)) {
            throw new IllegalArgumentException(name);
        }
        GspmPolicy policy = new GspmPolicy(name);
        setDefaults(
                policy,
                phase,
                Objects.requireNonNullElse(nullIfDefault(threshold), AlertThreshold.MEDIUM),
                Objects.requireNonNullElse(nullIfDefault(strength), AttackStrength.MEDIUM));
        addAndSave(registry, policy);
    }

    /**
     * Updates the defaults of a policy.
     *
     * @param phase the phase the defaults are for, {@code null} for all the rules of the policy.
     * @param threshold the default threshold, {@code null} or {@code DEFAULT} to leave unchanged.
     * @param strength the default strength, {@code null} or {@code DEFAULT} to leave unchanged.
     */
    static void updatePolicy(
            GspmRegistry registry,
            String name,
            GspmPhase phase,
            AlertThreshold threshold,
            AttackStrength strength) {
        change(
                registry,
                name,
                policy ->
                        setDefaults(
                                policy, phase, nullIfDefault(threshold), nullIfDefault(strength)));
    }

    private static void setDefaults(
            GspmPolicy policy, GspmPhase phase, AlertThreshold threshold, AttackStrength strength) {
        if (phase == null) {
            if (threshold != null) {
                policy.setDefaultThreshold(threshold);
            }
            if (strength != null) {
                policy.setDefaultStrength(strength);
            }
            return;
        }
        GspmRuleSet ruleSet = policy.findOrCreateCategoryRuleSet(GspmRuleSet.phaseKey(phase));
        if (threshold != null) {
            ruleSet.setThresholdEnum(threshold);
        }
        if (strength != null) {
            ruleSet.setStrengthEnum(strength);
        }
    }

    /**
     * Gets the default threshold of the rules of the phase (or of the policy, if {@code null}), the
     * one of the policy if the phase has none.
     *
     * @return the threshold, {@code null} if not defined.
     */
    static AlertThreshold getDefaultThreshold(GspmRegistry registry, String name, GspmPhase phase) {
        GspmPolicy policy = getPolicy(registry, name);
        synchronized (policy) {
            if (phase == null) {
                return policy.getDefaultThreshold().orElse(null);
            }
            return policy.getCategoryThreshold(GspmRuleSet.phaseKey(phase))
                    .or(policy::getDefaultThreshold)
                    .orElse(null);
        }
    }

    /**
     * Gets the default strength of the rules of the phase (or of the policy, if {@code null}), the
     * one of the policy if the phase has none.
     *
     * @return the strength, {@code null} if not defined.
     */
    static AttackStrength getDefaultStrength(GspmRegistry registry, String name, GspmPhase phase) {
        GspmPolicy policy = getPolicy(registry, name);
        synchronized (policy) {
            if (phase == null) {
                return policy.getDefaultStrength().orElse(null);
            }
            return policy.getCategoryStrength(GspmRuleSet.phaseKey(phase))
                    .or(policy::getDefaultStrength)
                    .orElse(null);
        }
    }

    static void removePolicy(GspmRegistry registry, String name) {
        GspmPolicy policy = getPolicy(registry, name);
        checkNotBuiltIn(name);
        // The files first, as otherwise the policy would not be removed (and it would be migrated
        // again on the next start), but it would no longer be in the registry to remove it again.
        // The legacy files before the policy file, so that if any can not be deleted the policy is
        // left as it was.
        // The source of the migration, if known (it's not after a restart), and any other legacy
        // file that would be migrated to the policy on the next start.
        Set<File> legacyFiles = new LinkedHashSet<>();
        if (policy.getLegacyFile() != null) {
            legacyFiles.add(policy.getLegacyFile());
        }
        legacyFiles.addAll(getMigratableLegacyFiles(Constant.getPoliciesDir(), policy));
        for (File legacyFile : legacyFiles) {
            if (legacyFile.exists() && !legacyFile.delete()) {
                throw new UncheckedIOException(
                        new IOException("Failed to delete the legacy policy file: " + legacyFile));
            }
        }
        if (!policy.deleteFile()) {
            throw new UncheckedIOException(
                    new IOException("Failed to delete the policy file: " + policy.getFile()));
        }
        registry.removePolicy(name);
    }

    /**
     * Gets the legacy files that would be migrated to the policy once removed, that is, the ones
     * with the policy and with no {@code .policy2} file of another policy named as them (as those
     * are not migrated).
     */
    private static List<File> getMigratableLegacyFiles(File dir, GspmPolicy policy) {
        File[] files = dir.listFiles((d, n) -> n.endsWith(LEGACY_EXTENSION));
        if (files == null) {
            return List.of();
        }
        return Arrays.stream(files)
                .filter(
                        f ->
                                !isFileOfOtherPolicy(
                                        new File(dir, baseName(f) + GspmPolicy.EXTENSION), policy))
                .filter(f -> isLegacyFileOf(f, policy.getName()))
                .toList();
    }

    private static boolean isFileOfOtherPolicy(File file, GspmPolicy policy) {
        return file.exists() && !file.equals(policy.getFile());
    }

    private static String baseName(File legacyFile) {
        String fileName = legacyFile.getName();
        return fileName.substring(0, fileName.length() - LEGACY_EXTENSION.length());
    }

    private static boolean isLegacyFileOf(File file, String name) {
        if (!file.isFile()) {
            return false;
        }
        try {
            GspmPolicy legacy = GspmLegacyImporter.importPolicy(file);
            return legacy != null && name.equals(legacy.getName());
        } catch (Exception e) {
            return false;
        }
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
        change(
                registry,
                policyName,
                policy ->
                        setThreshold(
                                policy,
                                getRule(registry, policyName, tool, ruleId),
                                nullIfDefault(threshold)));
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
        change(
                registry,
                policyName,
                policy ->
                        setStrength(
                                policy,
                                getRule(registry, policyName, tool, ruleId),
                                nullIfDefault(strength)));
    }

    /**
     * The settings of a rule, to configure it with {@link #configureRules}.
     *
     * @param ruleId the ID of the rule.
     * @param threshold the threshold, {@code null} to leave unchanged, {@code DEFAULT} clears the
     *     override.
     * @param strength the strength, {@code null} to leave unchanged, {@code DEFAULT} clears the
     *     override.
     */
    public record RuleSettings(int ruleId, AlertThreshold threshold, AttackStrength strength) {}

    /**
     * Configures rules of a tool, saving the policy once.
     *
     * <p>Setting the strength also enables the rule, as done when the policy is applied to a scan.
     * The strength is ignored for rules with no strength (e.g. passive rules).
     *
     * @param tool the tool the rules must be of.
     * @return the IDs of the rules that do not exist, those are not configured.
     */
    public static List<Integer> configureRules(
            GspmRegistry registry,
            String policyName,
            String tool,
            Collection<RuleSettings> settings) {
        List<Integer> unknownRules = new ArrayList<>();
        change(
                registry,
                policyName,
                policy -> {
                    Map<Integer, GspmRule> rules =
                            registry.getRulesByTool(tool, policyName).stream()
                                    .collect(
                                            Collectors.toMap(
                                                    GspmRule::getId, r -> r, (r1, r2) -> r1));
                    for (RuleSettings setting : settings) {
                        GspmRule rule = rules.get(setting.ruleId());
                        if (rule == null) {
                            unknownRules.add(setting.ruleId());
                            continue;
                        }
                        if (setting.strength() != null && rule.getAttackStrength() != null) {
                            setStrength(policy, rule, nullIfDefault(setting.strength()));
                            rule.setEnabled(true);
                        }
                        if (setting.threshold() != null) {
                            setThreshold(policy, rule, nullIfDefault(setting.threshold()));
                        }
                    }
                });
        return unknownRules;
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
        change(
                registry,
                policyName,
                policy -> {
                    for (int id : ruleIds) {
                        getRule(registry, policyName, tool, id).setEnabled(enabled);
                    }
                });
    }

    static void setAllRulesEnabled(
            GspmRegistry registry, String policyName, String tool, boolean enabled) {
        change(
                registry,
                policyName,
                policy ->
                        registry.getRulesByTool(tool, policyName)
                                .forEach(r -> r.setEnabled(enabled)));
    }

    /**
     * Sets the threshold of all the rules of the category, of every tool in the phase, overriding
     * the per rule thresholds.
     *
     * @param categoryKey the key of the category, without the one of the phase, e.g. {@code
     *     browser}.
     */
    static void setCategoryThreshold(
            GspmRegistry registry,
            String policyName,
            GspmPhase phase,
            String categoryKey,
            AlertThreshold threshold) {
        String key = categoryKey(phase, categoryKey);
        change(
                registry,
                policyName,
                policy -> {
                    policy.findOrCreateCategoryRuleSet(key)
                            .setThresholdEnum(nullIfDefault(threshold));
                    clearSubcategories(policy, key, rs -> rs.setThreshold(null));
                    for (GspmRule rule : categoryRules(registry, policy, key)) {
                        policy.clearRuleThreshold(rule.getId());
                    }
                });
    }

    /**
     * Sets the strength of all the rules of the category, of every tool in the phase, overriding
     * the per rule strengths.
     *
     * @param categoryKey the key of the category, without the one of the phase, e.g. {@code
     *     browser}.
     */
    static void setCategoryStrength(
            GspmRegistry registry,
            String policyName,
            GspmPhase phase,
            String categoryKey,
            AttackStrength strength) {
        String key = categoryKey(phase, categoryKey);
        change(
                registry,
                policyName,
                policy -> {
                    policy.findOrCreateCategoryRuleSet(key)
                            .setStrengthEnum(nullIfDefault(strength));
                    clearSubcategories(policy, key, rs -> rs.setStrength(null));
                    for (GspmRule rule : categoryRules(registry, policy, key)) {
                        policy.clearRuleStrength(rule.getId());
                    }
                });
    }

    /**
     * Clears the setting of the rule sets of the subcategories of the category, as they would take
     * precedence, removing the ones left with no settings.
     *
     * @param key the full key of the category, as returned by {@link #categoryKey(GspmPhase,
     *     String)}.
     * @param clear clears the setting of the rule set.
     */
    private static void clearSubcategories(
            GspmPolicy policy, String key, Consumer<GspmRuleSet> clear) {
        Iterator<GspmRuleSet> it = policy.getRuleSets().iterator();
        while (it.hasNext()) {
            GspmRuleSet rs = it.next();
            if (rs.getCategory() == null || !rs.getCategory().startsWith(key + ".")) {
                continue;
            }
            clear.accept(rs);
            if (rs.getThreshold() == null
                    && rs.getStrength() == null
                    && rs.getTags() == null
                    && rs.getStatus() == null
                    && rs.getRules() == null) {
                it.remove();
            }
        }
    }

    /**
     * Enables the rules of the tool in the given categories, disabling all the others of the tool.
     * The rules that are already enabled are not changed, so they keep their thresholds.
     *
     * @param categoryKeys the keys of the categories, without the one of the phase, e.g. {@code
     *     browser}.
     */
    static void setEnabledCategories(
            GspmRegistry registry,
            String policyName,
            String tool,
            Collection<String> categoryKeys) {
        change(
                registry,
                policyName,
                policy -> {
                    for (GspmRule rule : registry.getRulesByTool(tool, policyName)) {
                        rule.setEnabled(
                                categoryKeys.stream()
                                        .anyMatch(
                                                k ->
                                                        isInCategory(
                                                                rule,
                                                                categoryKey(rule.getPhase(), k))));
                    }
                });
    }

    /**
     * Tells whether or not the rule is in the category, that is the category of the rule is the
     * given one or one of its descendants.
     *
     * @param key the full key of the category, as returned by {@link #categoryKey(GspmPhase,
     *     String)}.
     */
    static boolean isInCategory(GspmRule rule, String key) {
        String ruleKey = GspmRuleSet.ruleCategoryKey(rule);
        return ruleKey.equals(key) || ruleKey.startsWith(key + ".");
    }

    /**
     * Returns the full key of the category of the phase, e.g. {@code phase.active.browser}.
     *
     * @param categoryKey the key of the category, without the one of the phase, e.g. {@code
     *     browser}.
     */
    static String categoryKey(GspmPhase phase, String categoryKey) {
        return GspmRuleSet.phaseKey(phase) + "." + categoryKey;
    }

    private static List<GspmRule> categoryRules(
            GspmRegistry registry, GspmPolicy policy, String key) {
        return registry.getAllRulesForPolicy(policy).stream()
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

    private static void checkNotBuiltIn(String name) {
        if (GspmRegistry.getDefaultPolicyName().equals(name)) {
            throw new IllegalArgumentException("The built-in policy can not be removed: " + name);
        }
    }

    /**
     * Changes the policy and saves it, while holding its lock. The change is undone if it fails or
     * the policy could not be saved.
     */
    private static void change(GspmRegistry registry, String name, Consumer<GspmPolicy> change) {
        GspmPolicy policy = getPolicy(registry, name);
        synchronized (policy) {
            List<GspmRuleSet> original = policy.copyRuleSets();
            try {
                change.accept(policy);
                save(policy);
            } catch (RuntimeException e) {
                policy.setRuleSets(original);
                throw e;
            }
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
