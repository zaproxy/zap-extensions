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

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.zaproxy.addon.commonlib.gspm.GspmPhase;
import org.zaproxy.addon.commonlib.gspm.GspmPolicy;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRule;

/**
 * The default policy of the Global Scan Policy Manager.
 *
 * <p>It is the {@link GspmRegistry#getCurrentPolicy() current policy} of the registry and the
 * default active scan policy of the core ({@link ScannerParam#getDefaultPolicy()}), which is
 * persisted, used for the active scans that do not specify a policy and selected by default in the
 * active scan dialog.
 *
 * <p>The passive scan rules (that is, the rules of {@link GspmPhase#PASSIVE}) are configured as
 * defined by this policy. The settings the rules had when first seen are kept and used for the
 * rules the policy does not configure, so that the result does not depend on the policies applied
 * before. The settings applied are not persisted by the rules' owners, the policy is applied again
 * in each ZAP session.
 *
 * <p>The first time it is used the settings of the passive scan rules are imported into the default
 * policy, normally the built-in {@link GspmRegistry#getDefaultPolicyName() Default Policy}, so that
 * they do not change.
 */
public class GspmDefaultPolicy implements GspmRegistry.RegistryListener {

    private static final Logger LOGGER = LogManager.getLogger(GspmDefaultPolicy.class);

    /** The settings of a rule. */
    private record RuleSettings(boolean enabled, AlertThreshold threshold) {}

    private final GspmRegistry registry;
    private final GspmParam param;
    private final Supplier<ScannerParam> scannerParam;

    /** The settings the passive rules had when first seen, by rule ID. */
    private final Map<Integer, RuleSettings> originalSettings = new ConcurrentHashMap<>();

    /** The thread importing a rule, whose save of the policy does not apply it to all the rules. */
    private final ThreadLocal<Boolean> importingRule = ThreadLocal.withInitial(() -> false);

    /** If the settings of the passive scan rules are being imported, in this ZAP session. */
    private volatile boolean importing;

    private volatile boolean started;

    /**
     * Constructs a {@code GspmDefaultPolicy}.
     *
     * @param registry the registry.
     * @param param the param, to know if the passive scan rules were imported.
     * @param scannerParam supplies the active scan options, where the default policy is persisted,
     *     might supply {@code null}.
     */
    public GspmDefaultPolicy(
            GspmRegistry registry, GspmParam param, Supplier<ScannerParam> scannerParam) {
        this.registry = Objects.requireNonNull(registry);
        this.param = Objects.requireNonNull(param);
        this.scannerParam = Objects.requireNonNull(scannerParam);
    }

    /**
     * Starts using the default policy, the policies must be already loaded.
     *
     * <p>Sets the default policy from the active scan options, and configures the passive scan
     * rules already registered and the ones registered later. Not started if there are no policies.
     */
    public synchronized void start() {
        if (started) {
            return;
        }
        String name = getPersistedName();
        if (name == null || registry.getPolicy(name) == null) {
            name = GspmRegistry.getDefaultPolicyName();
        }
        if (registry.getPolicy(name) == null) {
            LOGGER.warn("GSPM: no default policy available.");
            return;
        }
        started = true;
        importing = !param.isPassiveImported();
        if (importing) {
            // The rules registered later in this session are also imported.
            param.setPassiveImported();
            GspmPolicy policy = registry.getPolicy(name);
            registry.getAllRules().stream()
                    .filter(GspmDefaultPolicy::isPassive)
                    .forEach(rule -> importRule(rule, policy));
        }
        registry.addListener(this);
        if (name.equals(registry.getCurrentPolicy())) {
            currentPolicyChanged(name);
        } else {
            registry.setCurrentPolicy(name);
        }
    }

    /**
     * Stops using the default policy, the rules are no longer configured and get back the settings
     * they had when first seen.
     */
    public synchronized void stop() {
        if (!started) {
            return;
        }
        started = false;
        importing = false;
        registry.removeListener(this);
        for (GspmRule rule : registry.getAllRules()) {
            RuleSettings settings = originalSettings.get(rule.getId());
            if (settings != null && isPassive(rule)) {
                apply(rule, settings);
            }
        }
        originalSettings.clear();
    }

    /** Tells whether or not the default policy is being used, that is, it was started. */
    public boolean isStarted() {
        return started;
    }

    /**
     * Gets the name of the default policy.
     *
     * @return the name, {@code null} if none.
     */
    public String getName() {
        return registry.getCurrentPolicy();
    }

    /**
     * Sets the default policy.
     *
     * @param name the name of the policy.
     * @throws IllegalArgumentException if the policy does not exist.
     */
    public void setName(String name) {
        registry.setCurrentPolicy(name);
    }

    /** Called when the options changed, to follow the default policy set in the options. */
    public void optionsChanged() {
        if (!started) {
            return;
        }
        String name = getPersistedName();
        if (name != null && registry.getPolicy(name) != null) {
            registry.setCurrentPolicy(name);
        }
    }

    @Override
    public void ruleRegistered(GspmRule rule) {
        if (!isPassive(rule)) {
            return;
        }
        GspmPolicy policy = getPolicy();
        if (policy == null) {
            return;
        }
        if (importing) {
            importRule(rule, policy);
        }
        applyPolicy(policy, rule);
    }

    @Override
    public void ruleUnregistered(GspmRule rule) {
        originalSettings.remove(rule.getId());
    }

    @Override
    public void policyAdded(GspmPolicy policy) {
        if (policy.getName().equals(getName())) {
            applyToPassiveRules();
        }
    }

    @Override
    public void policySaved(GspmPolicy policy) {
        if (!importingRule.get() && policy.getName().equals(getName())) {
            applyToPassiveRules();
        }
    }

    @Override
    public void currentPolicyChanged(String policyName) {
        if (policyName == null) {
            // Removed, falls back to the built-in default policy, notified again.
            String name = GspmRegistry.getDefaultPolicyName();
            if (registry.getPolicy(name) != null) {
                registry.setCurrentPolicy(name);
            }
            return;
        }
        persist(policyName);
        applyToPassiveRules();
    }

    private GspmPolicy getPolicy() {
        String name = getName();
        return name != null ? registry.getPolicy(name) : null;
    }

    private void applyToPassiveRules() {
        GspmPolicy policy = getPolicy();
        if (policy == null) {
            return;
        }
        for (GspmRule rule : registry.getAllRules()) {
            if (isPassive(rule)) {
                applyPolicy(policy, rule);
            }
        }
    }

    /**
     * Applies the given policy to the given rule, or the settings the rule had when first seen if
     * the policy does not configure it.
     */
    private void applyPolicy(GspmPolicy policy, GspmRule rule) {
        RuleSettings original =
                originalSettings.computeIfAbsent(
                        rule.getId(),
                        id -> new RuleSettings(rule.isEnabled(), rule.getAlertThreshold()));
        Optional<AlertThreshold> threshold = policy.getEffectiveThreshold(rule);
        apply(
                rule,
                threshold
                        .map(t -> new RuleSettings(!AlertThreshold.OFF.equals(t), t))
                        .orElse(original));
    }

    private static void apply(GspmRule rule, RuleSettings settings) {
        try {
            AlertThreshold threshold = settings.threshold();
            if (threshold != null
                    && !AlertThreshold.OFF.equals(threshold)
                    && !threshold.equals(rule.getAlertThreshold())) {
                rule.setAlertThreshold(threshold);
            }
            rule.setEnabled(settings.enabled());
        } catch (Exception e) {
            LOGGER.warn("GSPM: failed to configure the rule {}", rule.getId(), e);
        }
    }

    /**
     * Imports the settings of the given rule into the given policy, if they differ from the ones
     * defined by the policy.
     */
    private void importRule(GspmRule rule, GspmPolicy policy) {
        synchronized (policy) {
            GspmRule view = GspmRegistry.getRuleForPolicy(rule, policy);
            boolean changed = false;
            if (!rule.isEnabled()) {
                if (view.isEnabled()) {
                    view.setEnabled(false);
                    changed = true;
                }
            } else {
                AlertThreshold threshold = rule.getAlertThreshold();
                if (threshold != null
                        && !AlertThreshold.OFF.equals(threshold)
                        && !threshold.equals(view.getAlertThreshold())) {
                    view.setAlertThreshold(threshold);
                    changed = true;
                } else if (!view.isEnabled()) {
                    view.setEnabled(true);
                    changed = true;
                }
            }
            if (!changed) {
                return;
            }
            importingRule.set(true);
            try {
                policy.save();
            } catch (IOException e) {
                LOGGER.warn("GSPM: failed to save the imported passive scan rule settings:", e);
            } finally {
                importingRule.set(false);
            }
        }
    }

    private String getPersistedName() {
        ScannerParam options = scannerParam.get();
        if (options == null) {
            return null;
        }
        String name = options.getDefaultPolicy();
        return name == null || name.isBlank() ? null : name;
    }

    private void persist(String name) {
        ScannerParam options = scannerParam.get();
        if (options == null || name.equals(options.getDefaultPolicy())) {
            return;
        }
        options.setDefaultPolicy(name);
        try {
            options.getConfig().save();
        } catch (ConfigurationException e) {
            LOGGER.warn("GSPM: failed to save the default policy:", e);
        }
    }

    private static boolean isPassive(GspmRule rule) {
        return rule.getPhase() == GspmPhase.PASSIVE;
    }
}
