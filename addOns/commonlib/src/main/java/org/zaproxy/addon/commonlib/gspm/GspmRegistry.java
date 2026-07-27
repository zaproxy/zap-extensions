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
package org.zaproxy.addon.commonlib.gspm;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.commonlib.gspm.internal.GspmLegacyImporter;

/**
 * Central registry for {@link GspmRule} instances across all add-ons.
 *
 * <p>Add-ons obtain the registry via {@link
 * org.zaproxy.addon.commonlib.ExtensionCommonlib#getGspmRegistry()} and call {@link
 * #registerRule(GspmRule)} during their startup / hook phase. They must call {@link
 * #unregisterRule(GspmRule)} or {@link #unregisterByTool(String)} when unloading.
 *
 * <p>Policies are named configurations of per-rule overrides. When a current policy is set, calls
 * to {@link #getRulesByTool(String)} return rule views that reflect that policy's configuration.
 * Tools can also request a specific policy via {@link #getRulesByTool(String, String)}.
 *
 * <p>Listeners are notified synchronously on the calling thread.
 *
 * <p>This is an internal class which may be changed at any time.
 *
 * @since 1.39.0
 */
public class GspmRegistry {

    private static final Logger LOGGER = LogManager.getLogger(GspmRegistry.class);

    /** The name of the built-in default policy that is always present. */
    public static final String DEFAULT_POLICY_NAME = "Default Policy";

    private final CopyOnWriteArrayList<GspmRule> rules = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<RegistryListener> listeners = new CopyOnWriteArrayList<>();

    private final Map<String, GspmTool> tools = Collections.synchronizedMap(new LinkedHashMap<>());

    private final Map<String, GspmPolicy> policies =
            Collections.synchronizedMap(new LinkedHashMap<>());
    private volatile String currentPolicyName;

    // -------------------------------------------------------------------------
    // Rule registration
    // -------------------------------------------------------------------------

    /**
     * Registers a scan rule.
     *
     * <p>Rule ids must be globally unique across all tools.
     *
     * @throws NullPointerException if {@code rule} is {@code null}
     * @throws IllegalArgumentException if a rule with the same id is already registered
     */
    public void registerRule(GspmRule rule) {
        Objects.requireNonNull(rule, "rule must not be null");
        if (rules.stream().anyMatch(r -> r.getId() == rule.getId())) {
            throw new IllegalArgumentException("Rule id already registered: " + rule.getId());
        }
        rules.add(rule);
        notifyRegistered(rule);
    }

    /**
     * Unregisters a previously registered rule.
     *
     * <p>No-op if the rule is not currently registered.
     */
    public void unregisterRule(GspmRule rule) {
        if (rules.remove(rule)) {
            notifyUnregistered(rule);
        }
    }

    /**
     * Unregisters all rules belonging to the given tool.
     *
     * <p>No-op if no rules are registered for that tool.
     */
    public void unregisterByTool(String tool) {
        Objects.requireNonNull(tool, "tool must not be null");
        List<GspmRule> toRemove =
                rules.stream().filter(r -> tool.equals(r.getTool())).collect(Collectors.toList());
        toRemove.forEach(
                r -> {
                    rules.remove(r);
                    notifyUnregistered(r);
                });
    }

    /**
     * Returns {@code true} if a rule with the given tool and id is already registered.
     *
     * <p>Note: {@link #registerRule} enforces globally unique ids across all tools. This method
     * checks tool+id, which is a subset of that constraint.
     */
    public boolean isRegistered(String tool, int id) {
        return rules.stream().anyMatch(r -> tool.equals(r.getTool()) && r.getId() == id);
    }

    // -------------------------------------------------------------------------
    // Rule queries
    // -------------------------------------------------------------------------

    /** Returns an unmodifiable snapshot of all currently registered rules. */
    public List<GspmRule> getAllRules() {
        return Collections.unmodifiableList(new ArrayList<>(rules));
    }

    /**
     * Returns all rules wrapped in a view that applies the given policy's configuration.
     *
     * <p>Getters on the returned rules resolve: per-rule policy override → policy default →
     * underlying rule value. Setters write back into the policy's per-rule config.
     *
     * @throws NullPointerException if {@code policy} is {@code null}
     */
    public List<GspmRule> getAllRulesForPolicy(GspmPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        return rules.stream()
                .map(r -> new PolicyRuleView(r, policy))
                .collect(Collectors.toUnmodifiableList());
    }

    /**
     * Returns rules for the given tool, applying the current policy if one is set.
     *
     * <p>If no current policy is set the underlying rule objects are returned directly. If a
     * current policy is set, each rule is wrapped in a view that reflects the policy's
     * configuration (falling through to the rule's own values for any field not overridden).
     *
     * <p>Returns an empty list if no rules are registered for that tool.
     */
    public List<GspmRule> getRulesByTool(String tool) {
        Objects.requireNonNull(tool, "tool must not be null");
        String policyName = currentPolicyName;
        if (policyName == null) {
            return rules.stream()
                    .filter(r -> tool.equals(r.getTool()))
                    .collect(Collectors.toUnmodifiableList());
        }
        return getRulesByTool(tool, policyName);
    }

    /**
     * Returns rules for the given tool with the named policy's configuration applied.
     *
     * <p>Each returned rule is a view over the underlying rule: getters resolve to the policy's
     * per-rule override first, then the policy's default threshold / strength, then the underlying
     * rule's own value. Setters write back into the policy's per-rule config so they can be used by
     * the UI to edit policy state.
     *
     * @throws IllegalArgumentException if no policy with that name exists
     */
    public List<GspmRule> getRulesByTool(String tool, String policyName) {
        Objects.requireNonNull(tool, "tool must not be null");
        Objects.requireNonNull(policyName, "policyName must not be null");
        GspmPolicy policy = policies.get(policyName);
        if (policy == null) {
            throw new IllegalArgumentException("Unknown policy: " + policyName);
        }
        return rules.stream()
                .filter(r -> tool.equals(r.getTool()))
                .map(r -> new PolicyRuleView(r, policy))
                .collect(Collectors.toUnmodifiableList());
    }

    // -------------------------------------------------------------------------
    // Tool registration
    // -------------------------------------------------------------------------

    /**
     * Registers a tool. Re-registering the same id replaces the previous entry.
     *
     * @throws NullPointerException if {@code tool} is {@code null}
     * @since 1.39.0
     */
    public void registerTool(GspmTool tool) {
        Objects.requireNonNull(tool, "tool must not be null");
        tools.put(tool.id(), tool);
    }

    /**
     * Returns the display name for the given tool key, or the tool key itself if no display name
     * has been registered.
     *
     * @since 1.39.0
     */
    public String getToolDisplayName(String toolKey) {
        GspmTool t = tools.get(toolKey);
        return t != null ? t.displayName() : toolKey;
    }

    /**
     * Returns the {@link GspmTool} registered for the given id, or {@code null} if none.
     *
     * @since 1.39.0
     */
    public GspmTool getTool(String id) {
        return tools.get(id);
    }

    // -------------------------------------------------------------------------
    // Policy management
    // -------------------------------------------------------------------------

    /**
     * Adds or replaces a policy.
     *
     * @throws NullPointerException if {@code policy} is {@code null}
     */
    public void addPolicy(GspmPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        policies.put(policy.getName(), policy);
    }

    /**
     * Removes the named policy.
     *
     * <p>If the removed policy was the current policy, the current policy is cleared.
     */
    public void removePolicy(String policyName) {
        Objects.requireNonNull(policyName, "policyName must not be null");
        policies.remove(policyName);
        if (policyName.equals(currentPolicyName)) {
            currentPolicyName = null;
        }
    }

    /** Returns the named policy, or {@code null} if no such policy exists. */
    public GspmPolicy getPolicy(String policyName) {
        Objects.requireNonNull(policyName, "policyName must not be null");
        return policies.get(policyName);
    }

    /** Returns an unmodifiable snapshot of all policies, in insertion order. */
    public Collection<GspmPolicy> getAllPolicies() {
        synchronized (policies) {
            return Collections.unmodifiableList(new ArrayList<>(policies.values()));
        }
    }

    /**
     * Sets the current (global) policy by name.
     *
     * @throws IllegalArgumentException if no policy with that name exists
     */
    public void setCurrentPolicy(String policyName) {
        Objects.requireNonNull(policyName, "policyName must not be null");
        if (!policies.containsKey(policyName)) {
            throw new IllegalArgumentException("Unknown policy: " + policyName);
        }
        this.currentPolicyName = policyName;
    }

    /** Clears the current policy so that rule queries return underlying rule values. */
    public void clearCurrentPolicy() {
        this.currentPolicyName = null;
    }

    /** Returns the name of the current policy, or {@code null} if none is set. */
    public String getCurrentPolicy() {
        return currentPolicyName;
    }

    // -------------------------------------------------------------------------
    // Listeners
    // -------------------------------------------------------------------------

    /** Adds a listener to be notified of registration changes. */
    public void addListener(RegistryListener listener) {
        listeners.add(Objects.requireNonNull(listener, "listener must not be null"));
    }

    /** Removes a previously added listener. */
    public void removeListener(RegistryListener listener) {
        listeners.remove(listener);
    }

    private void notifyRegistered(GspmRule rule) {
        listeners.forEach(l -> l.ruleRegistered(rule));
    }

    private void notifyUnregistered(GspmRule rule) {
        listeners.forEach(l -> l.ruleUnregistered(rule));
    }

    // -------------------------------------------------------------------------
    // Policy rule view
    // -------------------------------------------------------------------------

    /**
     * A {@link GspmRule} view over an underlying rule that applies a policy's configuration.
     * Getters resolve: per-rule policy override → policy default → underlying rule value. Setters
     * write back to the policy's per-rule config.
     */
    private static class PolicyRuleView implements GspmRule {

        private final GspmRule underlying;
        private final GspmPolicy policy;

        PolicyRuleView(GspmRule underlying, GspmPolicy policy) {
            this.underlying = underlying;
            this.policy = policy;
        }

        @Override
        public int getId() {
            return underlying.getId();
        }

        @Override
        public String getName() {
            return underlying.getName();
        }

        @Override
        public String getTool() {
            return underlying.getTool();
        }

        @Override
        public List<GspmCategory> getCategories() {
            return underlying.getCategories();
        }

        @Override
        public org.zaproxy.zap.control.AddOn.Status getStatus() {
            return underlying.getStatus();
        }

        @Override
        public String getAddOnName() {
            return underlying.getAddOnName();
        }

        @Override
        public java.util.Map<String, String> getAlertTags() {
            return underlying.getAlertTags();
        }

        @Override
        public AlertThreshold getAlertThreshold() {
            return policy.getEffectiveThreshold(underlying).orElse(underlying.getAlertThreshold());
        }

        @Override
        public void setAlertThreshold(AlertThreshold threshold) {
            policy.setRuleThreshold(underlying.getId(), underlying.getName(), threshold);
        }

        @Override
        public AttackStrength getAttackStrength() {
            if (underlying.getAttackStrength() == null) {
                return null;
            }
            return policy.getEffectiveStrength(underlying).orElse(underlying.getAttackStrength());
        }

        @Override
        public void setAttackStrength(AttackStrength strength) {
            if (underlying.getAttackStrength() == null) {
                return;
            }
            policy.setRuleStrength(underlying.getId(), underlying.getName(), strength);
        }

        @Override
        public boolean isEnabled() {
            return !AlertThreshold.OFF.equals(getAlertThreshold());
        }

        @Override
        public void setEnabled(boolean enabled) {
            if (!enabled) {
                policy.setRuleThreshold(
                        underlying.getId(), underlying.getName(), AlertThreshold.OFF);
            } else if (!isEnabled()) {
                policy.setRuleThreshold(underlying.getId(), underlying.getName(), null);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Policy persistence
    // -------------------------------------------------------------------------

    /**
     * Loads persisted policies from disk into this registry.
     *
     * <p>Reads all {@code .policy2} files from the given directory, then migrates any {@code
     * .policy} (legacy) files that do not already have a {@code .policy2} counterpart. Ensures the
     * built-in {@link #DEFAULT_POLICY_NAME} policy always exists, creating and saving it if absent.
     *
     * @param policiesDir the directory to scan and save policies in
     */
    public void loadPolicies(File policiesDir) {
        Set<String> policy2BaseNames = new HashSet<>();
        File[] policy2Files = policiesDir.listFiles((dir, n) -> n.endsWith(GspmPolicy.EXTENSION));
        if (policy2Files != null) {
            for (File f : policy2Files) {
                try {
                    addPolicy(GspmPolicy.load(f));
                    String base =
                            f.getName()
                                    .substring(
                                            0,
                                            f.getName().length() - GspmPolicy.EXTENSION.length());
                    policy2BaseNames.add(base);
                } catch (Exception e) {
                    LOGGER.error("Failed to load GSPM policy from {}", f, e);
                }
            }
        }

        Map<Integer, String> ruleNames = new HashMap<>();
        for (GspmRule rule : getAllRules()) {
            ruleNames.putIfAbsent(rule.getId(), rule.getName());
        }

        File[] legacyFiles = policiesDir.listFiles((dir, n) -> n.endsWith(".policy"));
        if (legacyFiles != null) {
            for (File legacyFile : legacyFiles) {
                String legacyName = legacyFile.getName();
                String base = legacyName.substring(0, legacyName.length() - ".policy".length());
                if (!policy2BaseNames.contains(base)) {
                    try {
                        GspmPolicy migrated =
                                GspmLegacyImporter.importPolicy(legacyFile, ruleNames);
                        if (migrated != null) {
                            if (getPolicy(migrated.getName()) == null) {
                                addPolicy(migrated);
                            }
                            migrated.save(policiesDir);
                            policy2BaseNames.add(base);
                            LOGGER.info(
                                    "Migrated legacy scan policy '{}' to GSPM format",
                                    migrated.getName());
                        }
                    } catch (Exception e) {
                        LOGGER.error("Failed to migrate legacy scan policy from {}", legacyFile, e);
                    }
                }
            }
        }

        if (getPolicy(DEFAULT_POLICY_NAME) == null) {
            GspmPolicy def = new GspmPolicy(DEFAULT_POLICY_NAME);
            def.setDefaultThreshold(AlertThreshold.MEDIUM);
            def.setDefaultStrength(AttackStrength.MEDIUM);
            addPolicy(def);
            try {
                def.save(policiesDir);
            } catch (IOException e) {
                LOGGER.error("Failed to save default GSPM policy", e);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Listener interface
    // -------------------------------------------------------------------------

    /**
     * Listener for changes to the registry.
     *
     * @since 1.39.0
     */
    public interface RegistryListener {

        /** Called after a rule has been registered. */
        void ruleRegistered(GspmRule rule);

        /** Called after a rule has been unregistered. */
        void ruleUnregistered(GspmRule rule);
    }
}
