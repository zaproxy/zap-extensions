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
import org.apache.commons.configuration.ConfigurationException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.core.scanner.PluginFactory;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Target;

public class ActiveScanJob extends AutomationJob {

    public static final String JOB_NAME = "activeScan";
    private static final String OPTIONS_METHOD_NAME = "getScannerParam";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_MAX_SCAN_DURATION = "maxScanDurationInMins";
    private static final String PARAM_POLICY = "policy";

    private ExtensionActiveScan extAScan;

    // Local copy
    private int maxDuration = 0;

    private String contextName;
    private String policy;

    public ActiveScanJob() {}

    private ExtensionActiveScan getExtAScan() {
        if (extAScan == null) {
            extAScan =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionActiveScan.class);
        }
        return extAScan;
    }

    private boolean verifyOrApplyCustomParameter(
            String name, String value, AutomationProgress progress) {
        switch (name) {
            case PARAM_CONTEXT:
                contextName = value;
                return true;
            case PARAM_MAX_SCAN_DURATION:
                if (progress != null) {
                    try {
                        Integer.parseInt(value);
                    } catch (NumberFormatException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.options.badint",
                                        this.getType(),
                                        name,
                                        value));
                    }
                } else {
                    maxDuration = Integer.parseInt(value);
                }
                // Don't consume this as we still want it to be applied to the ascan params
                return false;
            case PARAM_POLICY:
                if (progress != null) {
                    try {
                        this.getExtAScan().getPolicyManager().getPolicy(value);
                    } catch (ConfigurationException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.ascan.policy.name",
                                        this.getName(),
                                        value));
                    }
                } else {
                    policy = value;
                }
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public boolean applyCustomParameter(String name, String value) {
        return this.verifyOrApplyCustomParameter(name, value, null);
    }

    @Override
    public void verifyCustomParameter(String name, String value, AutomationProgress progress) {
        this.verifyOrApplyCustomParameter(name, value, progress);
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        return map;
    }

    @Override
    public void verifyJobSpecificData(LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        Object policyDefn = jobData.get("policyDefinition");
        if (policyDefn instanceof LinkedHashMap<?, ?>) {
            LinkedHashMap<?, ?> policyDefnData = (LinkedHashMap<?, ?>) policyDefn;
            JobUtils.parseAttackStrength(
                    policyDefnData.get("defaultStrength"), this.getName(), progress);
            JobUtils.parseAlertThreshold(
                    policyDefnData.get("defaultThreshold"), this.getName(), progress);

            ScanPolicy scanPolicy = new ScanPolicy();
            PluginFactory pluginFactory = scanPolicy.getPluginFactory();

            Object o = policyDefnData.get("rules");
            if (o instanceof ArrayList<?>) {
                ArrayList<?> ruleData = (ArrayList<?>) o;
                for (Object rule : ruleData) {
                    if (rule instanceof LinkedHashMap<?, ?>) {
                        LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                        Integer id = (Integer) ruleMap.get("id");
                        Plugin plugin = pluginFactory.getPlugin(id);
                        if (plugin != null) {
                            JobUtils.parseAttackStrength(
                                    ruleMap.get("strength"), this.getName(), progress);
                            JobUtils.parseAlertThreshold(
                                    ruleMap.get("threshold"), this.getName(), progress);
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
                                "automation.error.options.badlist", this.getName(), "rules", o));
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
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        ContextWrapper context;
        if (contextName != null) {
            context = env.getContextWrapper(contextName);
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown", contextName));
                return;
            }
        } else {
            context = env.getDefaultContextWrapper();
        }

        Target target = new Target(context.getContext());
        target.setRecurse(true);
        List<Object> contextSpecificObjects = new ArrayList<>();

        ScanPolicy scanPolicy = null;
        if (policy != null) {
            try {
                scanPolicy = this.getExtAScan().getPolicyManager().getPolicy(policy);
            } catch (ConfigurationException e) {
                // Error already raised above
            }
        } else {
            scanPolicy = this.getScanPolicy(jobData, progress);
        }
        if (scanPolicy != null) {
            contextSpecificObjects.add(scanPolicy);
        }

        int scanId = this.getExtAScan().startScan(target, null, contextSpecificObjects.toArray());

        long endTime = Long.MAX_VALUE;
        if (maxDuration > 0) {
            // The active scan should stop, if it doesnt we will stop it (after a few seconds
            // leeway)
            endTime =
                    System.currentTimeMillis()
                            + TimeUnit.MINUTES.toMillis(maxDuration)
                            + TimeUnit.SECONDS.toMillis(5);
        }

        // Wait for the active scan to finish
        ActiveScan scan;

        while (true) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                // Ignore
            }
            scan = this.getExtAScan().getScan(scanId);
            if (scan.isStopped()) {
                break;
            }
            if (System.currentTimeMillis() > endTime) {
                // It should have stopped but didn't (happens occasionally)
                this.getExtAScan().stopScan(scanId);
                break;
            }
        }
        progress.addJobResultData(createJobResultData(scanId));
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

    protected ScanPolicy getScanPolicy(LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        if (jobData == null) {
            return null;
        }
        Object policyDefn = jobData.get("policyDefinition");
        if (policyDefn == null) {
            return null;
        }
        LinkedHashMap<?, ?> policyDefnData = (LinkedHashMap<?, ?>) policyDefn;
        ScanPolicy scanPolicy = new ScanPolicy();

        // Set default strength
        AttackStrength st =
                JobUtils.parseAttackStrength(
                        policyDefnData.get("defaultStrength"), this.getName(), progress);
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
                        policyDefnData.get("defaultThreshold"), this.getName(), progress);
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
        Object o = policyDefnData.get("rules");
        if (o instanceof ArrayList<?>) {
            ArrayList<?> ruleData = (ArrayList<?>) o;
            for (Object rule : ruleData) {
                if (rule instanceof LinkedHashMap<?, ?>) {
                    LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                    Integer id = (Integer) ruleMap.get("id");
                    Plugin plugin = pluginFactory.getPlugin(id);
                    AttackStrength pluginSt =
                            JobUtils.parseAttackStrength(
                                    ruleMap.get("strength"), this.getName(), progress);
                    if (pluginSt != null) {
                        plugin.setAttackStrength(pluginSt);
                        plugin.setEnabled(true);
                        progress.info(
                                Constant.messages.getString(
                                        "automation.info.ascan.rule.setstrength",
                                        this.getName(),
                                        id,
                                        pluginSt.name()));
                    }
                    AlertThreshold pluginTh =
                            JobUtils.parseAlertThreshold(
                                    ruleMap.get("threshold"), this.getName(), progress);
                    if (pluginTh != null) {
                        plugin.setAlertThreshold(pluginTh);
                        plugin.setEnabled(true);
                        progress.info(
                                Constant.messages.getString(
                                        "automation.info.ascan.rule.setthreshold",
                                        this.getName(),
                                        id,
                                        pluginTh.name()));
                    }
                }
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

    public int getMaxDuration() {
        return maxDuration;
    }

    public String getPolicy() {
        return policy;
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
}
