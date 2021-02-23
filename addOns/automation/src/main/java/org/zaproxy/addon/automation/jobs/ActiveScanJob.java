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
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.model.Context;
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

    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_CONTEXT:
                contextName = value;
                return true;
            case PARAM_MAX_SCAN_DURATION:
                maxDuration = Integer.parseInt(value);
                // Don't consume this as we still want it to be applied to the ascan params
                return false;
            case PARAM_POLICY:
                policy = value;
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        return map;
    }

    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        Context context;
        if (contextName != null) {
            context = env.getContext(contextName);
            if (context == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.unknown",
                                env.getUrlStringForContext(context)));
                return;
            }
        } else {
            context = env.getDefaultContext();
        }

        Target target = new Target(context);
        target.setRecurse(true);
        List<Object> contextSpecificObjects = new ArrayList<>();

        ScanPolicy scanPolicy = null;
        if (policy != null) {
            try {
                scanPolicy = this.getExtAScan().getPolicyManager().getPolicy(policy);
            } catch (ConfigurationException e) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.ascan.policy.name", this.getName(), policy));
                return;
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
    }

    private AttackStrength parseAttackStrength(Object o, AutomationProgress progress) {
        AttackStrength strength = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                strength = AttackStrength.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.ascan.strength", this.getName(), o));
            }
        } else {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.ascan.strength", this.getName(), o));
        }
        return strength;
    }

    private AlertThreshold parseAlertThreshold(Object o, AutomationProgress progress) {
        AlertThreshold threshold = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                threshold = AlertThreshold.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.ascan.threshold", this.getName(), o));
            }
        } else if (o instanceof Boolean && (!(Boolean) o)) {
            // This will happen if OFF is not quoted
            threshold = AlertThreshold.OFF;
        } else {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.ascan.threshold", this.getName(), o));
        }
        return threshold;
    }

    protected ScanPolicy getScanPolicy(LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        if (jobData == null) {
            return null;
        }
        Object policyDefn = jobData.get("policyDefinition");
        if (policyDefn == null) {
            return null;
        }
        if (!(policyDefn instanceof LinkedHashMap<?, ?>)) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist",
                            this.getName(),
                            "policyDefinition",
                            policyDefn));
            return null;
        }
        LinkedHashMap<?, ?> policyDefnData = (LinkedHashMap<?, ?>) policyDefn;
        ScanPolicy scanPolicy = new ScanPolicy();

        // Set default strength
        AttackStrength st = parseAttackStrength(policyDefnData.get("defaultStrength"), progress);
        if (st != null) {
            scanPolicy.setDefaultStrength(st);
            progress.info(
                    Constant.messages.getString(
                            "automation.info.ascan.setdefstrength", this.getName(), st.name()));
        }

        // Set default threshold
        PluginFactory pluginFactory = scanPolicy.getPluginFactory();
        AlertThreshold th = parseAlertThreshold(policyDefnData.get("defaultThreshold"), progress);
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
                    if (plugin != null) {
                        AttackStrength pluginSt =
                                parseAttackStrength(ruleMap.get("strength"), progress);
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
                                parseAlertThreshold(ruleMap.get("threshold"), progress);
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
                    } else {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.ascan.rule.unknown", this.getName(), id));
                    }
                }
            }
        } else if (o != null) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.error.options.badlist", this.getName(), "rules", o));
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
