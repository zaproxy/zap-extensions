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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PassiveScanConfigJob extends AutomationJob {

    public static final String JOB_NAME = "passiveScan-config";
    private static final String OPTIONS_METHOD_NAME = "getPassiveScanParam";

    private ExtensionPassiveScan extPScan;

    public PassiveScanConfigJob() {}

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
    public void verifyJobSpecificData(LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        Object o = jobData.get("rules");
        if (o instanceof ArrayList<?>) {
            ArrayList<?> ruleData = (ArrayList<?>) o;
            for (Object rule : ruleData) {
                if (rule instanceof LinkedHashMap<?, ?>) {
                    LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                    Integer id = (Integer) ruleMap.get("id");
                    PluginPassiveScanner plugin = getExtPScan().getPluginPassiveScanner(id);
                    if (plugin == null) {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.pscan.rule.unknown", this.getName(), id));
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
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {
        // Configure any rules
        Object o = jobData.get("rules");
        ArrayList<?> ruleData = (ArrayList<?>) o;
        for (Object rule : ruleData) {
            if (rule instanceof LinkedHashMap<?, ?>) {
                LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                Integer id = (Integer) ruleMap.get("id");
                PluginPassiveScanner plugin = getExtPScan().getPluginPassiveScanner(id);
                AlertThreshold pluginTh =
                        JobUtils.parseAlertThreshold(
                                ruleMap.get("threshold"), this.getName(), progress);
                if (pluginTh != null && plugin != null) {
                    plugin.setAlertThreshold(pluginTh);
                    plugin.setEnabled(!AlertThreshold.OFF.equals(pluginTh));
                    progress.info(
                            Constant.messages.getString(
                                    "automation.info.pscan.rule.setthreshold",
                                    this.getName(),
                                    id,
                                    pluginTh.name()));
                }
            }
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
}
