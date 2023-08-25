/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.replacer.ExtensionReplacer;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;

public class ReplacerJob extends AutomationJob {

    private static final String JOB_NAME = "replacer";
    private static final String RESOURCES_DIR = "/org/zaproxy/zap/extension/replacer/resources/";

    private ExtensionReplacer extReplacer;

    private Data data;

    public ReplacerJob() {
        data = new Data(this);
    }

    private ExtensionReplacer getExtReplacer() {
        if (extReplacer == null) {
            extReplacer =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionReplacer.class);
        }
        return extReplacer;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                this.getParameters(),
                this.getName(),
                null,
                progress);

        Object ruleObject = jobData.get("rules");
        if (ruleObject == null) {
            progress.warn(
                    Constant.messages.getString(
                            "replacer.automation.error.norules", this.getName()));
            return;
        }
        if (!(ruleObject instanceof ArrayList)) {
            progress.error(
                    Constant.messages.getString(
                            "replacer.automation.error.badrules", this.getName()));
            return;
        }
        ArrayList<?> replacerData = (ArrayList<?>) ruleObject;
        for (Object replacerObject : replacerData.toArray()) {
            if (!(replacerObject instanceof LinkedHashMap)) {
                progress.error(
                        Constant.messages.getString(
                                "replacer.automation.error.badrule",
                                this.getName(),
                                replacerObject.toString()));
                return;
            }
            RuleData afd = new RuleData();
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) replacerObject, afd, this.getName(), null, progress);
            if (this.isValid(afd, progress)) {
                this.getData().addRule(afd);
            }
        }
    }

    private boolean isValid(RuleData afd, AutomationProgress progress) {
        boolean result = true;

        try {
            MatchType.valueOf(afd.getMatchType().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "replacer.automation.error.badmatch",
                            this.getName(),
                            validMatchTypes()));
            result = false;
        }
        if (StringUtils.isNotBlank(afd.getUrl())) {
            try {
                Pattern.compile(afd.getUrl());
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "replacer.automation.error.badurl", this.getName(), afd.getUrl()));
                result = false;
            }
        }
        if (StringUtils.isBlank(afd.getMatchString())) {
            progress.error(
                    Constant.messages.getString(
                            "replacer.automation.error.nomatchstring", this.getName()));
            result = false;
        }
        return result;
    }

    private static List<String> validMatchTypes() {
        return Stream.of(MatchType.values())
                .map(MatchType::name)
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toList());
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        if (JobUtils.unBox(this.getData().getParameters().getDeleteAllRules())) {
            this.getExtReplacer().getParams().clearRules();
            progress.info(
                    Constant.messages.getString(
                            "replacer.automation.info.rulesdelete", this.getName()));
        }

        List<RuleData> replacers = this.getData().getRules();
        if (replacers != null) {
            for (RuleData afd : replacers) {
                this.getExtReplacer().getParams().addRule(dataToReplacerRule(afd, progress));
            }
        }
    }

    protected static ReplacerParamRule dataToReplacerRule(
            RuleData data, AutomationProgress progress) {
        MatchType matchType = null;
        String matchTypeStr = data.getMatchType().toUpperCase(Locale.ROOT);
        try {
            matchType = MatchType.valueOf(matchTypeStr);
        } catch (Exception e) {
            if (progress != null) {
                progress.error(
                        Constant.messages.getString(
                                "replacer.automation.error.badmatch",
                                matchTypeStr,
                                validMatchTypes()));
            }
        }
        List<Integer> initiators = null;
        if (data.getInitiators() != null) {
            initiators = Arrays.stream(data.getInitiators()).collect(Collectors.toList());
        }

        return new ReplacerParamRule(
                data.getDescription(),
                data.getUrl(),
                matchType,
                data.getMatchString(),
                JobUtils.unBox(data.isMatchRegex()),
                data.getReplacementString(),
                initiators,
                true,
                JobUtils.unBox(data.getTokenProcessing()));
    }

    protected static void replacerRuleToData(ReplacerParamRule rule, RuleData data) {
        Integer[] initiators = null;
        if (rule.getInitiators() != null && rule.getInitiators().size() > 0) {
            initiators = rule.getInitiators().toArray(new Integer[0]);
        }

        data.setDescription(rule.getDescription());
        data.setUrl(rule.getUrl());
        data.setMatchType(rule.getMatchType().name().toLowerCase());
        data.setMatchString(rule.getMatchString());
        data.setMatchRegex(rule.isMatchRegex());
        data.setReplacementString(rule.getReplacement());
        data.setTokenProcessing(rule.isTokenProcessingEnabled());
        data.setInitiators(initiators);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getName() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getName() + "-max.yaml");
    }

    private String getResourceAsString(String name) {
        try (InputStream in = ExtensionReplacer.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Object getParamMethodObject() {
        return null;
    }

    @Override
    public String getParamMethodName() {
        return null;
    }

    @Override
    public void showDialog() {
        new ReplacerJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString("replacer.automation.dialog.summary", getRuleCount());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return getData().getParameters();
    }

    protected int getRuleCount() {
        if (this.getData().getRules() == null) {
            return 0;
        }
        return this.getData().getRules().size();
    }

    public static class Data extends JobData {
        private List<RuleData> rules;
        private Parameters parameters = new Parameters();

        public Data(AutomationJob job) {
            super(job);
        }

        public Parameters getParameters() {
            return parameters;
        }

        public void setParameters(Parameters parameters) {
            this.parameters = parameters;
        }

        public List<RuleData> getRules() {
            if (rules == null) {
                return Collections.emptyList();
            }
            return Collections.unmodifiableList(rules);
        }

        public void setRules(List<RuleData> rules) {
            this.rules = rules;
        }

        public void addRule(RuleData rule) {
            if (rules == null) {
                rules = new ArrayList<>();
            }
            this.rules.add(rule);
        }
    }

    public static class Parameters extends AutomationData {
        private Boolean deleteAllRules;

        public Boolean getDeleteAllRules() {
            return deleteAllRules;
        }

        public void setDeleteAllRules(Boolean deleteAllRules) {
            this.deleteAllRules = deleteAllRules;
        }
    }

    public static class RuleData extends AutomationData {
        private String description;
        private String url;
        private String matchType;
        private String matchString;
        private Boolean matchRegex;
        private String replacementString;
        private Boolean tokenProcessing;
        private Integer[] initiators;

        public RuleData() {}

        public RuleData(
                String description,
                String url,
                String matchType,
                String matchString,
                Boolean matchRegex,
                String replacementString,
                Boolean tokenProcessing,
                Integer[] initiators) {
            super();
            this.description = description;
            this.url = url;
            this.matchType = matchType;
            this.matchString = matchString;
            this.matchRegex = matchRegex;
            this.replacementString = replacementString;
            this.tokenProcessing = tokenProcessing;
            this.initiators = initiators;
        }

        public RuleData(RuleData data) {
            this.description = data.description;
            this.url = data.url;
            this.matchType = data.matchType;
            this.matchString = data.matchString;
            this.matchRegex = data.matchRegex;
            this.replacementString = data.replacementString;
            this.tokenProcessing = data.tokenProcessing;
            this.initiators = data.initiators;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getMatchType() {
            return matchType;
        }

        public void setMatchType(String matchType) {
            this.matchType = matchType;
        }

        public String getMatchString() {
            return matchString;
        }

        public void setMatchString(String matchString) {
            this.matchString = matchString;
        }

        public Boolean isMatchRegex() {
            return matchRegex;
        }

        public void setMatchRegex(Boolean matchRegex) {
            this.matchRegex = matchRegex;
        }

        public String getReplacementString() {
            return replacementString;
        }

        public void setReplacementString(String replacementString) {
            this.replacementString = replacementString;
        }

        public Integer[] getInitiators() {
            return initiators;
        }

        public void setInitiators(Integer[] initiators) {
            this.initiators = initiators;
        }

        public Boolean getTokenProcessing() {
            return tokenProcessing;
        }

        public void setTokenProcessing(Boolean tokenProcessing) {
            this.tokenProcessing = tokenProcessing;
        }
    }
}
