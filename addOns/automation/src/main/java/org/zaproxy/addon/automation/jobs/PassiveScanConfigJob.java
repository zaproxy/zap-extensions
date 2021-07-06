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
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanParam;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class PassiveScanConfigJob extends AutomationJob {

    public static final String JOB_NAME = "passiveScan-config";
    private static final String OPTIONS_METHOD_NAME = "getPassiveScanParam";
    private static final String PARAM_ID = "id";

    private static final String PARAM_ENABLE_TAGS = "enableTags";

    private ExtensionPassiveScan extPScan;
    private boolean enableTags = false;

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
    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_ENABLE_TAGS:
                enableTags = Boolean.parseBoolean(value);
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public boolean verifyCustomParameter(String name, String value, AutomationProgress progress) {
        switch (name) {
            case PARAM_ENABLE_TAGS:
                String s = value.trim().toLowerCase();
                if (!"true".equals(s) && !"false".equals(s)) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.options.badbool",
                                    this.getName(),
                                    name,
                                    value));
                }

                if (Model.getSingleton().getOptionsParam().getParamSet(PassiveScanParam.class)
                        == null) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.pscan.nooptions", this.getName()));
                }
                return true;
            default:
                // Ignore
                break;
        }
        return false;
    }

    @Override
    public void verifyJobSpecificData(AutomationProgress progress) {
        Object o = this.getJobData().get("rules");
        if (o instanceof ArrayList<?>) {
            ArrayList<?> ruleData = (ArrayList<?>) o;
            for (Object rule : ruleData) {
                if (rule instanceof LinkedHashMap<?, ?>) {
                    LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
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
                        }
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
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        // Configure any rules
        Object o = this.getJobData().get("rules");
        ArrayList<?> ruleData = (ArrayList<?>) o;
        if (ruleData != null) {
            for (Object rule : ruleData) {
                if (rule instanceof LinkedHashMap<?, ?>) {
                    LinkedHashMap<?, ?> ruleMap = (LinkedHashMap<?, ?>) rule;
                    Integer id = (Integer) ruleMap.get(PARAM_ID);
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
        // enable / disable pscan tags
        PassiveScanParam pscanParam =
                Model.getSingleton().getOptionsParam().getParamSet(PassiveScanParam.class);
        if (pscanParam != null) {
            pscanParam
                    .getAutoTagScanners()
                    .forEach(tagScanner -> tagScanner.setEnabled(enableTags));
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

    public boolean isEnableTags() {
        return enableTags;
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
