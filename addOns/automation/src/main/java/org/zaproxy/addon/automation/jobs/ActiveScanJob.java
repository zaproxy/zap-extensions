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
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.gui.ActiveScanJobDialog;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.users.User;

public class ActiveScanJob extends AutomationJob {

    public static final String JOB_NAME = "activeScan";
    private static final String OPTIONS_METHOD_NAME = "getScannerParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_POLICY = "policy";

    private static final String RULES_ELEMENT_NAME = "rules";

    private ExtensionActiveScan extAScan;

    private Parameters parameters = new Parameters();
    private PolicyDefinition policyDefinition = new PolicyDefinition();
    private Data data;

    public ActiveScanJob() {
        data = new Data(this, this.parameters, this.policyDefinition);
    }

    private ExtensionActiveScan getExtAScan() {
        if (extAScan == null) {
            extAScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return extAScan;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get("parameters");
        JobUtils.applyParamsToObject(params, this.parameters, this.getName(), null, progress);

        this.verifyUser(this.getParameters().getUser(), progress);

        // Parse the policy defn
        Object policyDefn = this.getJobData().get("policyDefinition");
        if (policyDefn instanceof LinkedHashMap<?, ?>) {
            LinkedHashMap<?, ?> policyDefnData = (LinkedHashMap<?, ?>) policyDefn;

            JobUtils.applyParamsToObject(
                    policyDefnData,
                    this.policyDefinition,
                    this.getName(),
                    new String[] {RULES_ELEMENT_NAME},
                    progress);

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
                                            ruleMap.get("strength"), this.getName(), progress);
                            AlertThreshold threshold =
                                    JobUtils.parseAlertThreshold(
                                            ruleMap.get("threshold"), this.getName(), progress);

                            Rule rule = new Rule();
                            rule.setId(id);
                            rule.setName(plugin.getName());
                            if (threshold != null) {
                                rule.setThreshold(threshold.name().toLowerCase());
                            }
                            if (strength != null) {
                                rule.setStrength(strength.name().toLowerCase());
                            }
                            this.getData().getPolicyDefinition().addRule(rule);

                        } else {
                            progress.warn(
                                    Constant.messages.getString(
                                            "automation.error.ascan.rule.unknown",
                                            this.getName(),
                                            id));
                        }
                    }
                }
            } else if (o != null) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.options.badlist",
                                this.getName(),
                                RULES_ELEMENT_NAME,
                                o));
            }

        } else if (policyDefn != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist",
                            this.getName(),
                            "policyDefinition",
                            policyDefn));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {PARAM_POLICY, PARAM_CONTEXT},
                progress,
                this.getPlan().getEnv());
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        return map;
    }

    @Override
    public boolean supportsMonitorTests() {
        return true;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        getExtAScan().setPanelSwitch(false);

        ContextWrapper context;
        if (this.getParameters().getContext() != null) {
            context = env.getContextWrapper(this.getParameters().getContext());
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown",
                                this.getParameters().getContext()));
                return;
            }
        } else {
            context = env.getDefaultContextWrapper();
        }

        Target target = new Target(context.getContext());
        target.setRecurse(true);
        List<Object> contextSpecificObjects = new ArrayList<>();
        User user = this.getUser(this.getParameters().getUser(), progress);

        ScanPolicy scanPolicy = null;
        if (!StringUtils.isEmpty(this.getParameters().getPolicy())) {
            try {
                scanPolicy =
                        this.getExtAScan()
                                .getPolicyManager()
                                .getPolicy(this.getParameters().getPolicy());
            } catch (ConfigurationException e) {
                // Error already raised above
            }
        } else {
            scanPolicy = this.getScanPolicy(progress);
        }
        if (scanPolicy != null) {
            contextSpecificObjects.add(scanPolicy);
        }

        int scanId = this.getExtAScan().startScan(target, user, contextSpecificObjects.toArray());

        long endTime = Long.MAX_VALUE;
        if (JobUtils.unBox(this.getParameters().getMaxScanDurationInMins()) > 0) {
            // The active scan should stop, if it doesnt we will stop it (after a few seconds
            // leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(
                                    this.getParameters().getMaxScanDurationInMins())
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the active scan to finish
        ActiveScan scan;
        boolean forceStop = false;

        while (true) {
            this.sleep(500);
            scan = this.getExtAScan().getScan(scanId);
            if (scan.isStopped()) {
                break;
            }
            if (!this.runMonitorTests(progress) || System.currentTimeMillis() > endTime) {
                forceStop = true;
                break;
            }
        }
        if (forceStop) {
            this.getExtAScan().stopScan(scanId);
            progress.info(Constant.messages.getString("automation.info.jobstopped", getType()));
        }
        progress.addJobResultData(createJobResultData(scanId));

        getExtAScan().setPanelSwitch(true);
    }

    @Override
    public List<JobResultData> getJobResultData() {
        ActiveScan lastScan = this.getExtAScan().getLastScan();
        if (lastScan != null) {
            return createJobResultData(lastScan.getId());
        }
        return new ArrayList<>();
    }

    private List<JobResultData> createJobResultData(int scanId) {
        List<JobResultData> list = new ArrayList<>();
        list.add(new ActiveScanJobResultData(this.getName(), this.getExtAScan().getScan(scanId)));
        return list;
    }

    protected ScanPolicy getScanPolicy(AutomationProgress progress) {
        ScanPolicy scanPolicy = new ScanPolicy();

        // Set default strength
        AttackStrength st =
                JobUtils.parseAttackStrength(
                        this.getData().getPolicyDefinition().getDefaultStrength(),
                        this.getName(),
                        progress);
        if (st != null) {
            scanPolicy.setDefaultStrength(st);
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.setdefstrength", this.getName(), st.name()));
        }

        // Set default threshold
        PluginFactory pluginFactory = scanPolicy.getPluginFactory();
        AlertThreshold th =
                JobUtils.parseAlertThreshold(
                        this.getData().getPolicyDefinition().getDefaultThreshold(),
                        this.getName(),
                        progress);
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
                            "automation.info.ascan.setdefthreshold", this.getName(), th.name()));
        }

        // Configure any rules
        for (Rule rule : this.getData().getPolicyDefinition().getRules()) {
            Plugin plugin = pluginFactory.getPlugin(rule.getId());
            if (plugin == null) {
                // Will have already warned about this
                continue;
            }
            AttackStrength pluginSt =
                    JobUtils.parseAttackStrength(rule.getStrength(), this.getName(), progress);
            if (pluginSt != null) {
                plugin.setAttackStrength(pluginSt);
                plugin.setEnabled(true);
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.rule.setstrength",
                                this.getName(),
                                rule.getId(),
                                pluginSt.name()));
            }
            AlertThreshold pluginTh =
                    JobUtils.parseAlertThreshold(rule.getThreshold(), this.getName(), progress);
            if (pluginTh != null) {
                plugin.setAlertThreshold(pluginTh);
                plugin.setEnabled(!AlertThreshold.OFF.equals(pluginTh));
                progress.info(
                        Constant.messages.getString(
                                "automation.info.ascan.rule.setthreshold",
                                this.getName(),
                                rule.getId(),
                                pluginTh.name()));
            }
        }
        return scanPolicy;
    }

    @Override
    public boolean isExcludeParam(String param) {
        switch (param) {
            case "allowAttackOnStart":
            case "attackPolicy":
            case "hostPerScan":
            case "maxChartTimeInMins":
            case "maxResultsToList":
            case "maxScansInUI":
            case "promptInAttackMode":
            case "promptToClearFinishedScans":
            case "rescanInAttackMode":
            case "showAdvancedDialog":
            case "targetParamsInjectable":
            case "targetParamsEnabledRPC":
                return true;
            default:
                return false;
        }
    }

    @Override
    public String getSummary() {
        String context = this.getParameters().getContext();
        if (StringUtils.isEmpty(context)) {
            context = Constant.messages.getString("automation.dialog.default");
        }
        return Constant.messages.getString("automation.dialog.ascan.summary", context);
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
        return Order.ATTACK;
    }

    @Override
    public Object getParamMethodObject() {
        return this.getExtAScan();
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public void showDialog() {
        new ActiveScanJobDialog(this).setVisible(true);
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

    public static class Data extends JobData {
        private Parameters parameters;
        private PolicyDefinition policyDefinition;

        public Data(AutomationJob job, Parameters parameters, PolicyDefinition policyDefinition) {
            super(job);
            this.parameters = parameters;
            this.policyDefinition = policyDefinition;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public PolicyDefinition getPolicyDefinition() {
            return policyDefinition;
        }
    }

    public static class PolicyDefinition extends AutomationData {
        private String defaultStrength;
        private String defaultThreshold;
        private List<Rule> rules = new ArrayList<>();

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
    }

    public static class Parameters extends AutomationData {

        private String context;
        private String user;
        private String policy;
        private Integer maxRuleDurationInMins;
        private Integer maxScanDurationInMins;
        private Boolean addQueryParam;
        private String defaultPolicy;
        private Integer delayInMs;
        private Boolean handleAntiCSRFTokens;
        private Boolean injectPluginIdInHeader;
        private Boolean scanHeadersAllRequests;
        private Integer threadPerHost;

        public Parameters() {}

        public String getContext() {
            return context;
        }

        public void setContext(String context) {
            this.context = context;
        }

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }

        public Integer getMaxRuleDurationInMins() {
            return maxRuleDurationInMins;
        }

        public void setMaxRuleDurationInMins(Integer maxRuleDurationInMins) {
            this.maxRuleDurationInMins = maxRuleDurationInMins;
        }

        public Integer getMaxScanDurationInMins() {
            return maxScanDurationInMins;
        }

        public void setMaxScanDurationInMins(Integer maxScanDurationInMins) {
            this.maxScanDurationInMins = maxScanDurationInMins;
        }

        public Boolean getAddQueryParam() {
            return addQueryParam;
        }

        public void setAddQueryParam(Boolean addQueryParam) {
            this.addQueryParam = addQueryParam;
        }

        public String getDefaultPolicy() {
            return defaultPolicy;
        }

        public void setDefaultPolicy(String defaultPolicy) {
            this.defaultPolicy = defaultPolicy;
        }

        public Integer getDelayInMs() {
            return delayInMs;
        }

        public void setDelayInMs(Integer delayInMs) {
            this.delayInMs = delayInMs;
        }

        public Boolean getHandleAntiCSRFTokens() {
            return handleAntiCSRFTokens;
        }

        public void setHandleAntiCSRFTokens(Boolean handleAntiCSRFTokens) {
            this.handleAntiCSRFTokens = handleAntiCSRFTokens;
        }

        public Boolean getInjectPluginIdInHeader() {
            return injectPluginIdInHeader;
        }

        public void setInjectPluginIdInHeader(Boolean injectPluginIdInHeader) {
            this.injectPluginIdInHeader = injectPluginIdInHeader;
        }

        public Boolean getScanHeadersAllRequests() {
            return scanHeadersAllRequests;
        }

        public void setScanHeadersAllRequests(Boolean scanHeadersAllRequests) {
            this.scanHeadersAllRequests = scanHeadersAllRequests;
        }

        public Integer getThreadPerHost() {
            return threadPerHost;
        }

        public void setThreadPerHost(Integer threadPerHost) {
            this.threadPerHost = threadPerHost;
        }
    }
}
