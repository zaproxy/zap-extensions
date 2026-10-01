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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;

/**
 * Generic {@link GspmRuleSource} that also implements {@link AddOnInstallationStatusListener},
 * shared by scan-rule sources (active scan, passive scan, ...) so each doesn't need to duplicate
 * the add-on install/uninstall bookkeeping.
 *
 * <p>Construct one per tool, supplying: the tool id and display name, a way to fetch every
 * currently available rule (paired with its owning add-on, if any) for the initial bulk
 * registration, and a way to fetch the rules contributed by one specific add-on once it's
 * installed. This class keeps the {@link GspmRegistry} in sync with add-on installs/uninstalls at
 * runtime, tracking which rules came from which add-on so they can be cleanly removed again.
 *
 * <p>The supplied functions are invoked lazily (every time rules are (re)fetched), so it's safe to
 * construct this before the underlying rule source (e.g. a {@code PolicyManager} or {@code
 * PassiveScannersManager}) is available, as long as it is available by the time registration
 * actually happens.
 *
 * @since 1.45.0
 */
public class GspmScanRuleRegistrar implements GspmRuleSource, AddOnInstallationStatusListener {

    private static final Logger LOGGER = LogManager.getLogger(GspmScanRuleRegistrar.class);

    private final String toolId;
    private final Supplier<String> toolDisplayName;
    private final GspmPhase phase;
    private final Supplier<List<RuleOwner>> allRulesSupplier;
    private final Function<AddOn, List<GspmRule>> rulesForAddOn;

    private final Map<AddOn, List<GspmRule>> rulesByAddOn = new HashMap<>();
    private final Map<Integer, GspmRule> registeredRules = new HashMap<>();

    private GspmRegistry registry;

    /**
     * @param toolId the stable tool key to register rules under, e.g. {@code "ascan"}
     * @param toolDisplayName supplies the tool's i18n display name; evaluated lazily so this can be
     *     constructed before i18n messages are available
     * @param phase the fixed, tool-independent top-level grouping this tool's rules appear under in
     *     the GSPM dialog's tree; multiple tools may share the same phase
     * @param allRulesSupplier supplies every currently available rule, paired with its owning
     *     add-on (or {@code null} if not contributed by an add-on), for the initial registration
     * @param rulesForAddOn supplies the rules contributed by a specific add-on, called when that
     *     add-on is installed at runtime
     */
    public GspmScanRuleRegistrar(
            String toolId,
            Supplier<String> toolDisplayName,
            GspmPhase phase,
            Supplier<List<RuleOwner>> allRulesSupplier,
            Function<AddOn, List<GspmRule>> rulesForAddOn) {
        this.toolId = toolId;
        this.toolDisplayName = toolDisplayName;
        this.phase = phase;
        this.allRulesSupplier = allRulesSupplier;
        this.rulesForAddOn = rulesForAddOn;
    }

    @Override
    public void registerRulesWithGspm(GspmRegistry reg) {
        this.registry = reg;
        reg.registerTool(new GspmTool(toolId, toolDisplayName.get(), phase));
        List<RuleOwner> owners = allRulesSupplier.get();
        for (RuleOwner owner : owners) {
            registerRule(owner.rule(), owner.addOn());
        }
        LOGGER.debug("GSPM: registered {} '{}' rules", owners.size(), toolId);
    }

    @Override
    public void unregisterRulesFromGspm(GspmRegistry reg) {
        reg.unregisterByTool(toolId);
        rulesByAddOn.clear();
        registeredRules.clear();
        this.registry = null;
        LOGGER.debug("GSPM: unregistered '{}' rules", toolId);
    }

    /**
     * Registers a single rule directly, outside the bulk {@link #registerRulesWithGspm} and the
     * add-on install/uninstall driven {@link #update} — e.g. a script-backed scan rule added by the
     * user at runtime, not tied to any add-on's lifecycle.
     *
     * <p>No-op if {@link #registerRulesWithGspm} hasn't been called yet (or {@link
     * #unregisterRulesFromGspm} has, since), or if a rule with this id is already registered —
     * checked against the shared {@link GspmRegistry}, not just this source, so a runtime clash
     * with another tool (e.g. active scan, HTTP passive scan) is rejected here rather than throwing
     * out of {@link GspmRegistry#registerRule(GspmRule)}.
     */
    public void ruleAdded(GspmRule rule) {
        if (registry == null) {
            return;
        }
        registry.getRule(rule.getId())
                .ifPresentOrElse(
                        existing ->
                                LOGGER.error(
                                        "Attempted to register rule '{}' with ID {} already"
                                                + " registered by tool '{}' as '{}'",
                                        rule.getName(),
                                        rule.getId(),
                                        existing.getTool(),
                                        existing.getName()),
                        () -> registerRule(rule, null));
    }

    /**
     * Unregisters a single previously-registered rule directly, by id — the counterpart to {@link
     * #ruleAdded(GspmRule)}, e.g. a script-backed scan rule removed by the user at runtime.
     *
     * <p>No-op if this source doesn't currently have a rule registered under this id.
     */
    public void ruleRemoved(int id) {
        if (registry == null) {
            return;
        }
        GspmRule rule = registeredRules.remove(id);
        if (rule != null) {
            registry.unregisterRule(rule);
        }
    }

    /**
     * Reacts to add-ons being installed or uninstalled while ZAP is running, keeping GSPM's view of
     * this tool's rules in sync.
     */
    @Override
    public void update(StatusUpdate statusUpdate) {
        switch (statusUpdate.getStatus()) {
            case INSTALLED:
                handleAddOnInstalled(statusUpdate.getAddOn());
                break;
            case SOFT_UNINSTALL:
            case UNINSTALL:
                handleAddOnUninstalled(statusUpdate.getAddOn());
                break;
            default:
        }
    }

    private void handleAddOnInstalled(AddOn addOn) {
        if (registry == null) {
            return;
        }
        int count = 0;
        for (GspmRule rule : rulesForAddOn.apply(addOn)) {
            if (registry.isRegistered(rule.getId())) {
                continue;
            }
            registerRule(rule, addOn);
            count++;
        }
        if (count > 0) {
            LOGGER.debug(
                    "GSPM: registered {} '{}' rules for installed add-on {}",
                    count,
                    toolId,
                    addOn.getName());
        }
    }

    /**
     * Unregisters the rules previously registered for {@code addOn}, using the rules recorded at
     * registration time rather than re-querying the underlying rule source, whose entries for this
     * add-on may already have been removed by the time this is called.
     */
    private void handleAddOnUninstalled(AddOn addOn) {
        if (registry == null) {
            return;
        }
        List<GspmRule> rules = rulesByAddOn.remove(addOn);
        if (rules == null || rules.isEmpty()) {
            return;
        }
        rules.forEach(
                rule -> {
                    registry.unregisterRule(rule);
                    registeredRules.remove(rule.getId());
                });
        LOGGER.debug(
                "GSPM: unregistered {} '{}' rules for uninstalled add-on {}",
                rules.size(),
                toolId,
                addOn.getName());
    }

    private void registerRule(GspmRule rule, AddOn addOn) {
        registry.registerRule(rule);
        registeredRules.put(rule.getId(), rule);
        if (addOn != null) {
            rulesByAddOn.computeIfAbsent(addOn, a -> new ArrayList<>()).add(rule);
        }
    }

    /** Pairs a {@link GspmRule} with the {@link AddOn} that contributed it, if known. */
    public record RuleOwner(GspmRule rule, AddOn addOn) {}
}
