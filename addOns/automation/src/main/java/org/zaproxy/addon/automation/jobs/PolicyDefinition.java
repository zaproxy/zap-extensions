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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.ascan.ScanPolicy;

public class PolicyDefinition extends AutomationData {

    protected static final String RULES_ELEMENT_NAME = "rules";

    private String defaultStrength;
    private String defaultThreshold;
    private List<Rule> rules = new ArrayList<>();

    protected static List<Rule> parsePolicyDefinition(
            LinkedHashMap<?, ?> policyDefnData, String jobName, AutomationProgress progress) {
        List<Rule> rules = new ArrayList<>();
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

                        Rule rule = new Rule();
                        rule.setId(id);
                        rule.setName(plugin.getName());
                        if (threshold != null) {
                            rule.setThreshold(threshold.name().toLowerCase());
                        }
                        if (strength != null) {
                            rule.setStrength(strength.name().toLowerCase());
                        }
                        rules.add(rule);

                    } else {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.ascan.rule.unknown", jobName, id));
                    }
                }
            }
        } else if (o != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist", jobName, RULES_ELEMENT_NAME, o));
        }
        return rules;
    }

    public String getDefaultStrength() {
        return defaultStrength;
    }

    public void setDefaultStrength(String defaultStrength) {
        this.defaultStrength = defaultStrength;
    }

    public String getDefaultThreshold() {
        return defaultThreshold;
    }

    public void setDefaultThreshold(String defaultThreshold) {
        this.defaultThreshold = defaultThreshold;
    }

    public List<Rule> getRules() {
        return rules.stream().map(Rule::copy).collect(Collectors.toList());
    }

    public void addRule(Rule rule) {
        this.rules.add(rule);
    }

    public void removeRule(Rule rule) {
        this.rules.remove(rule);
    }

    public void setRules(List<Rule> rules) {
        this.rules = rules;
    }

    public static class Rule extends AutomationData {
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

        public int getId() {
            return id;
        }

        public void setId(int id) {
            this.id = id;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getThreshold() {
            return threshold;
        }

        public void setThreshold(String threshold) {
            this.threshold = threshold;
        }

        public String getStrength() {
            return strength;
        }

        public void setStrength(String strength) {
            this.strength = strength;
        }
    }
}
