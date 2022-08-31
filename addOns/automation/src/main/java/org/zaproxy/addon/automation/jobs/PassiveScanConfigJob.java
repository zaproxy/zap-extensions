/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import java.util.Map;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.PassiveScanConfigJobDialog;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanParam;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PassiveScanConfigJob extends AutomationJob {

    public static final String JOB_NAME = "passiveScan-config";
    private static final String OPTIONS_METHOD_NAME = "getPassiveScanParam";
    private static final String PARAM_ID = "id";

    private static final String PARAM_ENABLE_TAGS = "enableTags";

    private static final String[] IGNORE_PARAMS = new String[] {PARAM_ENABLE_TAGS};

    private ExtensionPassiveScan extPScan;

    private Parameters parameters = new Parameters();
    private Parameters originalParameters = new Parameters();
    private Data data;

    public PassiveScanConfigJob() {
        data = new Data(this, this.parameters);
    }

    private ExtensionPassiveScan getExtPScan() {
        if (extPScan == null) {
            extPScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionPassiveScan.class);
        }
        return extPScan;
    }

    @Override
    public void planStarted() {
        // Save the current state
        AutomationProgress tempProgress = new AutomationProgress();
        JobUtils.applyObjectToObject(
                JobUtils.getJobOptions(this, tempProgress),
                this.originalParameters,
                this.getName(),
                IGNORE_PARAMS,
                tempProgress,
                this.getPlan().getEnv());
    }

    @Override
    public void planFinished() {
        // Revert the state
        AutomationProgress tempProgress = new AutomationProgress();
        JobUtils.applyObjectToObject(
                this.originalParameters,
                JobUtils.getJobOptions(this, tempProgress),
                this.getName(),
                IGNORE_PARAMS,
                tempProgress,
                this.getPlan().getEnv());
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get("parameters");
        JobUtils.applyParamsToObject(params, this.parameters, this.getName(), null, progress);
        Object o = this.getJobData().get("rules");
        if (o instanceof ArrayList<?>) {
            ArrayList<?> ruleData = (ArrayList<?>) o;
            for (Object ruleObj : ruleData) {
                if (ruleObj instanceof LinkedHashMap<?, ?>) {
                    LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) ruleObj;
                    try {
                        Object idObj = ruleMap.get(PARAM_ID);
                        if (idObj == null) {
                            progress.info(
                                    Constant.messages.getString(
                                            "automation.info.pscan.rule.noid", this.getName()));
                            continue;
                        }
                        int id = Integer.parseInt(idObj.toString());
                        PluginPassiveScanner plugin = getExtPScan().getPluginPassiveScanner(id);
                        if (plugin == null) {
                            progress.warn(
                                    Constant.messages.getString(
                                            "automation.error.pscan.rule.unknown",
                                            this.getName(),
                                            id));
                            continue;
                        }
                        AlertThreshold pluginTh =
                                JobUtils.parseAlertThreshold(
                                        ruleMap.get("threshold"), this.getName(), progress);

                        Rule rule = new Rule();
                        rule.setId(id);
                        rule.setName(plugin.getName());
                        if (pluginTh != null) {
                            rule.setThreshold(pluginTh.name().toLowerCase());
                        }
                        this.getData().addRule(rule);
                    } catch (NumberFormatException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.options.badint",
                                        this.getType(),
                                        PARAM_ID,
                                        ruleMap.get(PARAM_ID)));
                    }
                }
            }
        } else if (o != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist", this.getName(), "rules", o));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        AutomationEnvironment env = null;
        if (this.getPlan() != null) {
            // Should only happen in unit tests
            env = this.getPlan().getEnv();
        }
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                IGNORE_PARAMS,
                progress,
                env);
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        // Configure any rules
        for (Rule rule : this.getData().getRules()) {
            PluginPassiveScanner plugin = getExtPScan().getPluginPassiveScanner(rule.getId());
            AlertThreshold pluginTh =
                    JobUtils.parseAlertThreshold(rule.getThreshold(), this.getName(), progress);
            if (pluginTh != null && plugin != null) {
                plugin.setAlertThreshold(pluginTh);
                plugin.setEnabled(!AlertThreshold.OFF.equals(pluginTh));
                progress.info(
                        Constant.messages.getString(
                                "automation.info.pscan.rule.setthreshold",
                                this.getName(),
                                rule.getId(),
                                pluginTh.name()));
            }
        }
        // enable / disable pscan tags
        PassiveScanParam pscanParam =
                Model.getSingleton().getOptionsParam().getParamSet(PassiveScanParam.class);
        if (pscanParam != null) {
            pscanParam
                    .getAutoTagScanners()
                    .forEach(
                            tagScanner ->
                                    tagScanner.setEnabled(this.getParameters().getEnableTags()));
        }
    }

    @Override
    public boolean isExcludeParam(String param) {
        switch (param) {
            case "confirmRemoveAutoTagScanner":
                return true;
            default:
                return false;
        }
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
    }

    @Override
    public Object getParamMethodObject() {
        return getExtPScan();
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public void showDialog() {
        new PassiveScanConfigJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.pscanconfig.summary", this.getData().getRules().size());
    }

    public static class Rule extends AutomationData {
        private int id;
        private String name;
        private String threshold;

        public Rule() {}

        public Rule(int id, String name, String threshold) {
            this.id = id;
            this.name = name;
            this.threshold = threshold;
        }

        public Rule copy() {
            return new Rule(id, name, threshold);
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
    }

    public static class Data extends JobData {
        private Parameters parameters;
        private List<Rule> rules = new ArrayList<>();

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public List<Rule> getRules() {
            return rules.stream().map(r -> r.copy()).collect(Collectors.toList());
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
    }

    public static class Parameters extends AutomationData {
        private Integer maxAlertsPerRule;
        private Boolean scanOnlyInScope = true;
        private Integer maxBodySizeInBytesToScan;
        private Boolean enableTags = false;

        public Parameters() {}

        public Integer getMaxAlertsPerRule() {
            return maxAlertsPerRule;
        }

        public void setMaxAlertsPerRule(Integer maxAlertsPerRule) {
            this.maxAlertsPerRule = maxAlertsPerRule;
        }

        public Boolean getScanOnlyInScope() {
            return scanOnlyInScope;
        }

        public void setScanOnlyInScope(Boolean scanOnlyInScope) {
            this.scanOnlyInScope = scanOnlyInScope;
        }

        public Integer getMaxBodySizeInBytesToScan() {
            return maxBodySizeInBytesToScan;
        }

        public void setMaxBodySizeInBytesToScan(Integer maxBodySizeInBytesToScan) {
            this.maxBodySizeInBytesToScan = maxBodySizeInBytesToScan;
        }

        public Boolean getEnableTags() {
            return enableTags;
        }

        public void setEnableTags(Boolean enableTags) {
            this.enableTags = enableTags;
        }
    }
}
