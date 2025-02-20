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
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.gui.ActiveScanJobDialog;
import org.zaproxy.addon.commonlib.Constants;
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
    private static final String PARAM_USER = "user";

    private ExtensionActiveScan extAScan;

    private Parameters parameters = new Parameters();
    private PolicyDefinition policyDefinition = new PolicyDefinition();
    private Data data;

    public ActiveScanJob() {
        data = new Data(this, this.parameters, this.policyDefinition);
    }

    @Override
    public boolean supportsAlertTests() {
        return true;
    }

    @Override
    public String getKeyAlertTestsResultData() {
        return ActiveScanJobResultData.KEY;
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

        for (Object key : jobData.keySet().toArray()) {
            switch (key.toString()) {
                case "parameters":
                    LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get(key);
                    JobUtils.applyParamsToObject(
                            params, this.parameters, this.getName(), null, progress);
                    break;
                case "policyDefinition":
                case "name":
                case "tests":
                case "type":
                    // Handled before we get here
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.element.unknown", this.getName(), key));

                    break;
            }
        }
        policyDefinition.parsePolicyDefinition(
                jobData.get("policyDefinition"), this.getName(), progress);
        this.verifyUser(this.getParameters().getUser(), progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {PARAM_POLICY, PARAM_CONTEXT, PARAM_USER},
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
        if (StringUtils.isNotEmpty(this.getParameters().getContext())) {
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
            scanPolicy =
                    this.getData().getPolicyDefinition().getScanPolicy(this.getName(), progress);
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
        int previousScanProgress = 0;
        long lastProgressOutput = System.currentTimeMillis();

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

            var scanProgress = scan.getProgress();
            var now = System.currentTimeMillis();

            if (scanProgress > previousScanProgress || now - lastProgressOutput > 5000) {
                progress.info("Active scan progress: " + scanProgress + "%");
                previousScanProgress = scanProgress;

                scan.getHostProcesses().forEach(
                    hostProcess -> hostProcess.getRunning().forEach(
                        running -> {
                            var requestCount = hostProcess.getPluginRequestCount(running.getId());
                            progress.info(
                                    String.format(
                                            "%s (%s) - %s requests",
                                            running.getName(),
                                            running.getId(),
                                            requestCount
                                    )
                            );
                        }
                    )
                );

                lastProgressOutput = now;
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

    @Getter
    public static class Data extends JobData {
        private final Parameters parameters;
        private final PolicyDefinition policyDefinition;

        public Data(AutomationJob job, Parameters parameters, PolicyDefinition policyDefinition) {
            super(job);
            this.parameters = parameters;
            this.policyDefinition = policyDefinition;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String context = "";
        private String user = "";
        private String policy = "";
        private Integer maxRuleDurationInMins = 0;
        private Integer maxScanDurationInMins = 0;
        private Boolean addQueryParam = false;
        private String defaultPolicy = "";
        private Integer delayInMs = 0;
        private Boolean handleAntiCSRFTokens = true;
        private Boolean injectPluginIdInHeader = false;
        private Boolean scanHeadersAllRequests = false;
        private Integer threadPerHost = Constants.getDefaultThreadCount();
        private Integer maxAlertsPerRule = 0;

        public Integer getThreadPerHost() {
            if (JobUtils.unBox(threadPerHost) <= 0) {
                // Don't return zero or less - this will cause problems
                return null;
            }
            return threadPerHost;
        }
    }
}
