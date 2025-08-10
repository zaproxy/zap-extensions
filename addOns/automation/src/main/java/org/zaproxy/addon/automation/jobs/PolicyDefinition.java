/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import static java.util.function.Predicate.not;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.ascan.ScanPolicy;

@Getter
@Setter
public class PolicyDefinition extends AutomationData {

    private static final String DEFAULT_STRENGTH_KEY = "defaultStrength";
    private static final String DEFAULT_THRESHOLD_KEY = "defaultThreshold";
    private static final String ALERT_TAGS_KEY = "alertTags";
    protected static final String RULES_ELEMENT_NAME = "rules";

    private String defaultStrength = JobUtils.strengthToI18n(AttackStrength.MEDIUM.name());
    private String defaultThreshold = JobUtils.thresholdToI18n(AlertThreshold.MEDIUM.name());

    @JsonProperty(ALERT_TAGS_KEY)
    private AlertTagRuleConfig alertTagRule = new AlertTagRuleConfig();

    private List<Rule> rules = new ArrayList<>();

    public void parsePolicyDefinition(
            Object policyDefnObj, String jobName, AutomationProgress progress) {

        if (policyDefnObj == null) {
            this.defaultStrength = null;
            return;
        }
        if (policyDefnObj instanceof LinkedHashMap<?, ?>) {
            @SuppressWarnings("unchecked")
            LinkedHashMap<Object, Object> policyDefnData =
                    (LinkedHashMap<Object, Object>) policyDefnObj;

            checkAndSetDefault(policyDefnData, DEFAULT_STRENGTH_KEY, AttackStrength.MEDIUM.name());
            checkAndSetDefault(policyDefnData, DEFAULT_THRESHOLD_KEY, AlertThreshold.MEDIUM.name());

            if (policyDefnData.isEmpty() || undefinedDefinition(policyDefnData)) {
                this.defaultStrength = null;
                return;
            }

            JobUtils.applyParamsToObject(
                    policyDefnData,
                    this,
                    jobName,
                    new String[] {
                        PolicyDefinition.RULES_ELEMENT_NAME, PolicyDefinition.ALERT_TAGS_KEY
                    },
                    progress);

            this.rules = new ArrayList<>();
            ScanPolicy scanPolicy = new ScanPolicy();
            PluginFactory pluginFactory = scanPolicy.getPluginFactory();

            Object o = policyDefnData.get(RULES_ELEMENT_NAME);
            if (o instanceof ArrayList<?>) {
                ArrayList<?> ruleData = (ArrayList<?>) o;
                for (Object ruleObj : ruleData) {
                    if (ruleObj instanceof LinkedHashMap<?, ?>) {
                        LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) ruleObj;
                        Integer id = (Integer) ruleMap.get("id");
                        Plugin plugin = pluginFactory.getPlugin(id);
                        if (plugin != null) {
                            AttackStrength strength =
                                    JobUtils.parseAttackStrength(
                                            ruleMap.get("strength"), jobName, progress);
                            AlertThreshold threshold =
                                    JobUtils.parseAlertThreshold(
                                            ruleMap.get("threshold"), jobName, progress);
                            this.rules.add(buildRule(plugin, strength, threshold));
                        } else {
                            progress.warn(
                                    Constant.messages.getString(
                                            "automation.error.ascan.rule.unknown",
                                            jobName,
                                            String.valueOf(id)));
                        }
                    }
                }
            } else if (o != null) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.options.badlist",
                                jobName,
                                RULES_ELEMENT_NAME,
                                o));
            }

            if (policyDefnData.containsKey(ALERT_TAGS_KEY)
                    && policyDefnData.get(ALERT_TAGS_KEY)
                            instanceof LinkedHashMap<?, ?> alertTagsData) {
                this.alertTagRule = new AlertTagRuleConfig();
                if (alertTagsData.get("include") != null) {
                    alertTagRule.setIncludePatterns(
                            JobUtils.verifyRegexes(
                                            alertTagsData.get("include"),
                                            getAlertTagsKey(jobName, "include"),
                                            progress)
                                    .stream()
                                    .map(Pattern::compile)
                                    .toList());
                }
                if (alertTagsData.get("exclude") != null) {
                    alertTagRule.setExcludePatterns(
                            JobUtils.verifyRegexes(
                                            alertTagsData.get("exclude"),
                                            getAlertTagsKey(jobName, "exclude"),
                                            progress)
                                    .stream()
                                    .map(Pattern::compile)
                                    .toList());
                }
                if (alertTagsData.get("strength") != null) {
                    AttackStrength strength =
                            JobUtils.parseAttackStrength(
                                    alertTagsData.get("strength"),
                                    getAlertTagsKey(jobName, "strength"),
                                    progress);
                    if (strength != null) {
                        alertTagRule.setStrength(strength);
                    }
                }
                if (alertTagsData.get("threshold") != null) {
                    AlertThreshold threshold =
                            JobUtils.parseAlertThreshold(
                                    alertTagsData.get("threshold"),
                                    getAlertTagsKey(jobName, "threshold"),
                                    progress);
                    if (threshold != null) {
                        alertTagRule.setThreshold(threshold);
                    }
                }
            } else if (policyDefnData.containsKey(ALERT_TAGS_KEY)) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.options.badtype",
                                jobName,
                                ALERT_TAGS_KEY,
                                policyDefnData.get(ALERT_TAGS_KEY).getClass().getCanonicalName()));
            }
        } else if (policyDefnObj != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist",
                            jobName,
                            "policyDefinition",
                            policyDefnObj));
        }
    }

    List<Rule> getEffectiveRules() {
        return computeEffectiveRules(this.alertTagRule, this.rules);
    }

    public static List<Rule> computeEffectiveRules(
            AlertTagRuleConfig alertTagRule, List<Rule> rules) {
        if (alertTagRule == null
                || (alertTagRule.getIncludePatterns().isEmpty()
                        && alertTagRule.getExcludePatterns().isEmpty())) {
            return rules;
        }
        Map<Integer, Rule> effectiveRulesMap =
                rules.stream()
                        .collect(
                                LinkedHashMap::new,
                                (map, rule) -> map.put(rule.getId(), rule),
                                LinkedHashMap::putAll);
        List<Plugin> allRules = new ScanPolicy().getPluginFactory().getAllPlugin();
        allRules.stream()
                .filter(plugin -> plugin.getAlertTags() != null)
                .filter(
                        not(
                                plugin ->
                                        anyStringMatchesAnyPattern(
                                                plugin.getAlertTags().keySet(),
                                                alertTagRule.getExcludePatterns())))
                .filter(
                        plugin ->
                                anyStringMatchesAnyPattern(
                                        plugin.getAlertTags().keySet(),
                                        alertTagRule.getIncludePatterns()))
                .forEach(
                        plugin ->
                                effectiveRulesMap.computeIfAbsent(
                                        plugin.getId(),
                                        id ->
                                                buildRule(
                                                        plugin,
                                                        alertTagRule.getStrength(),
                                                        alertTagRule.getThreshold())));
        return List.copyOf(effectiveRulesMap.values());
    }

    private static Rule buildRule(
            Plugin plugin, AttackStrength strength, AlertThreshold threshold) {
        Rule rule = new Rule();
        rule.setId(plugin.getId());
        rule.setName(plugin.getName());
        if (strength != null) {
            rule.setStrength(strength.name().toLowerCase(Locale.ROOT));
        }
        if (threshold != null) {
            rule.setThreshold(threshold.name().toLowerCase(Locale.ROOT));
        }
        return rule;
    }

    private static boolean anyStringMatchesAnyPattern(
            Collection<String> strings, List<Pattern> patterns) {
        if (strings == null || strings.isEmpty() || patterns == null || patterns.isEmpty()) {
            return false;
        }
        return strings.stream()
                .anyMatch(key -> patterns.stream().anyMatch(p -> p.matcher(key).matches()));
    }

    private static String getAlertTagsKey(String jobName, String field) {
        return MessageFormat.format("{0}.policyDefinition.alertTags.{1}", jobName, field);
    }

    private static void checkAndSetDefault(
            LinkedHashMap<Object, Object> policyDefnData, String key, String value) {
        if (policyDefnData.containsKey(key) && policyDefnData.get(key) == null) {
            policyDefnData.put(key, value);
        }
    }

    private static boolean undefinedDefinition(Map<?, ?> policyDefnData) {
        Object rules = policyDefnData.get(RULES_ELEMENT_NAME);
        boolean rulesInvalid = false;
        if (rules instanceof List<?>) {
            rulesInvalid = ((List<?>) rules).isEmpty();
        } else if ((String) rules == null) {
            rulesInvalid = true;
        }
        return (String) policyDefnData.get(DEFAULT_STRENGTH_KEY) == null
                && (String) policyDefnData.get(DEFAULT_THRESHOLD_KEY) == null
                && rulesInvalid;
    }

    public ScanPolicy getScanPolicy(String jobName, AutomationProgress progress) {
        if (getDefaultStrength() == null) {
            // Nothing defined
            return null;
        }

        ScanPolicy scanPolicy = new ScanPolicy();

        // Set default strength
        AttackStrength st = JobUtils.parseAttackStrength(getDefaultStrength(), jobName, progress);
        if (st != null) {
            scanPolicy.setDefaultStrength(st);
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.setdefstrength", jobName, st.name()));
        }

        // Set default threshold
        PluginFactory pluginFactory = scanPolicy.getPluginFactory();
        AlertThreshold th = JobUtils.parseAlertThreshold(getDefaultThreshold(), jobName, progress);
        if (th != null) {
            scanPolicy.setDefaultThreshold(th);
            if (th == AlertThreshold.OFF) {
                for (Plugin plugin : pluginFactory.getAllPlugin()) {
                    plugin.setEnabled(false);
                }
            } else {
                scanPolicy.setDefaultThreshold(th);
            }
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.setdefthreshold", jobName, th.name()));
        }

        // Configure any rules
        for (Rule rule : getEffectiveRules()) {
            Plugin plugin = pluginFactory.getPlugin(rule.getId());
            if (plugin == null) {
                // Will have already warned about this
                continue;
            }
            AttackStrength pluginSt =
                    JobUtils.parseAttackStrength(rule.getStrength(), jobName, progress);
            if (pluginSt != null) {
                plugin.setAttackStrength(pluginSt);
                plugin.setEnabled(true);
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.rule.setstrength",
                                jobName,
                                String.valueOf(rule.getId()),
                                pluginSt.name()));
            }
            AlertThreshold pluginTh =
                    JobUtils.parseAlertThreshold(rule.getThreshold(), jobName, progress);
            if (pluginTh != null) {
                plugin.setAlertThreshold(pluginTh);
                plugin.setEnabled(!AlertThreshold.OFF.equals(pluginTh));
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.rule.setthreshold",
                                jobName,
                                String.valueOf(rule.getId()),
                                pluginTh.name()));
            }
        }
        return scanPolicy;
    }

    public void addRule(Rule rule) {
        this.rules.add(rule);
    }

    public void removeRule(Rule rule) {
        this.rules.remove(rule);
    }

    @Getter
    @Setter
    public static class Rule extends AutomationData {
        @JsonInclude(JsonInclude.Include.ALWAYS)
        private int id;

        private String name;
        private String threshold;
        private String strength;

        public Rule() {}

        public Rule(int id, String name, String threshold, String strength) {
            this.id = id;
            this.name = name;
            this.threshold = threshold;
            this.strength = strength;
        }

        public Rule copy() {
            return new Rule(id, name, threshold, strength);
        }
    }

    @Getter
    @Setter
    @AllArgsConstructor
    @NoArgsConstructor
    @EqualsAndHashCode(callSuper = false)
    public static class AlertTagRuleConfig extends AutomationData {
        @JsonProperty("include")
        @NonNull
        private List<Pattern> includePatterns = List.of();

        @JsonProperty("exclude")
        @NonNull
        private List<Pattern> excludePatterns = List.of();

        @NonNull private AttackStrength strength = AttackStrength.MEDIUM;
        @NonNull private AlertThreshold threshold = AlertThreshold.MEDIUM;

        public AlertTagRuleConfig copy() {
            return new AlertTagRuleConfig(
                    List.copyOf(includePatterns),
                    List.copyOf(excludePatterns),
                    strength,
                    threshold);
        }
    }
}
