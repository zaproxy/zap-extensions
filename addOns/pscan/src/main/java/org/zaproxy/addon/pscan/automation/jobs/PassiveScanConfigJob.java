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
package org.zaproxy.addon.pscan.automation.jobs;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.PassiveScanRuleProvider;
import org.zaproxy.addon.pscan.PassiveScanRuleProvider.PassiveScanRule;
import org.zaproxy.addon.pscan.automation.internal.PassiveScanConfigJobDialog;
import org.zaproxy.addon.pscan.internal.PassiveScannerOptions;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PassiveScanConfigJob extends AutomationJob {

    public static final String JOB_NAME = "passiveScan-config";
    private static final String OPTIONS_METHOD_NAME = "getPassiveScannerOptions";
    private static final String PARAM_ID = "id";

    private static final String PARAM_ENABLE_TAGS = "enableTags";
    private static final String PARAM_DISABLE_ALL_RULES = "disableAllRules";

    private static final String[] IGNORE_PARAMS =
            new String[] {PARAM_ENABLE_TAGS, PARAM_DISABLE_ALL_RULES};

    private final ExtensionPassiveScan2 pscan;

    private Parameters parameters = new Parameters();
    private Parameters originalParameters = new Parameters();
    private Data data;

    public PassiveScanConfigJob() {
        this.pscan =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionPassiveScan2.class);
        data = new Data(this, this.parameters);
    }

    @Override
    public void planStarted() {
        // Save the current state
        AutomationProgress tempProgress = new AutomationProgress();
        JobUtils.applyObjectToObject(
                JobUtils.getJobOptions(this, tempProgress),
                this.originalParameters,
                this.getName(),
                new String[] {
                    "scanFuzzerMessages",
                    "autoTagScanners",
                    "passiveScanThreads",
                    "confirmRemoveAutoTagScanner",
                    "config"
                },
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
                                            "pscan.automation.info.pscan.rule.noid",
                                            this.getName()));
                            continue;
                        }
                        int id = Integer.parseInt(idObj.toString());
                        PluginPassiveScanner plugin =
                                pscan.getPassiveScannersManager().getScanRule(id);
                        String pluginName = "";
                        if (plugin != null) {
                            pluginName = plugin.getName();
                        } else {
                            boolean provided = false;
                            for (PassiveScanRuleProvider prov : pscan.getPscanRuleProviders()) {
                                PassiveScanRule rule = prov.getRule(id);
                                if (rule != null) {
                                    provided = true;
                                    pluginName = rule.i18nName();
                                }
                            }
                            if (!provided) {
                                progress.warn(
                                        Constant.messages.getString(
                                                "pscan.automation.error.pscan.rule.unknown",
                                                this.getName(),
                                                String.valueOf(id)));
                                continue;
                            }
                        }
                        AlertThreshold pluginTh =
                                JobUtils.parseAlertThreshold(
                                        ruleMap.get("threshold"), this.getName(), progress);

                        Rule rule = new Rule();
                        rule.setId(id);
                        rule.setName(pluginName);
                        if (pluginTh != null) {
                            rule.setThreshold(pluginTh.name().toLowerCase());
                        }
                        this.getData().addRule(rule);
                    } catch (NumberFormatException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "pscan.automation.error.options.badint",
                                        this.getType(),
                                        PARAM_ID,
                                        ruleMap.get(PARAM_ID)));
                    }
                }
            }
        } else if (o != null) {
            progress.warn(
                    Constant.messages.getString(
                            "pscan.automation.error.options.badlist", this.getName(), "rules", o));
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
        if (Boolean.TRUE.equals(this.getData().getParameters().getDisableAllRules())) {
            pscan.getPassiveScannersManager()
                    .getScanRules()
                    .forEach(pscan -> pscan.setEnabled(false));
            pscan.getPscanRuleProviders().forEach(prov -> prov.disableAllRules());
        }

        for (Rule rule : this.getData().getRules()) {
            AlertThreshold pluginTh =
                    JobUtils.parseAlertThreshold(rule.getThreshold(), this.getName(), progress);
            if (pluginTh == null) {
                continue;
            }
            PluginPassiveScanner plugin =
                    pscan.getPassiveScannersManager().getScanRule(rule.getId());
            if (plugin != null) {
                plugin.setAlertThreshold(pluginTh);
                plugin.setEnabled(!AlertThreshold.OFF.equals(pluginTh));
                progress.info(
                        Constant.messages.getString(
                                "pscan.automation.info.pscan.rule.setthreshold",
                                this.getName(),
                                String.valueOf(rule.getId()),
                                pluginTh.name()));
            } else {
                for (PassiveScanRuleProvider prov : pscan.getPscanRuleProviders()) {
                    if (prov.setThreshold(rule.id, pluginTh)) {
                        break;
                    }
                }
            }
        }
        // enable / disable pscan tags
        getPassiveScannerOptions()
                .getAutoTagScanners()
                .forEach(tagScanner -> tagScanner.setEnabled(this.getParameters().getEnableTags()));
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
        return this;
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    public PassiveScannerOptions getPassiveScannerOptions() {
        return pscan.getModel().getOptionsParam().getParamSet(PassiveScannerOptions.class);
    }

    @Override
    public void showDialog() {
        new PassiveScanConfigJobDialog(this).setVisible(true);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getType() + "-max.yaml");
    }

    private static String getResourceAsString(String fileName) {
        try (InputStream in = PassiveScanConfigJob.class.getResourceAsStream(fileName)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("pscan.automation.error.nofile", fileName));
        }
        return "";
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "pscan.automation.dialog.pscanconfig.summary", this.getData().getRules().size());
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Rule extends AutomationData {
        private int id;
        private String name = "";
        private String threshold = "";

        public Rule copy() {
            return new Rule(id, name, threshold);
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

    @Setter
    @Getter
    public static class Parameters extends AutomationData {
        private Integer maxAlertsPerRule = 0;
        private Boolean scanOnlyInScope = true;
        private Integer maxBodySizeInBytesToScan = 0;
        private Boolean enableTags = false;
        private Boolean disableAllRules = false;
    }
}
