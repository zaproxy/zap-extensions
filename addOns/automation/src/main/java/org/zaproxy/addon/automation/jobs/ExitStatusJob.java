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

import java.util.LinkedHashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.gui.ExitStatusJobDialog;

public class ExitStatusJob extends AutomationJob {

    public static final String JOB_NAME = "exitStatus";

    private Data data;
    private Parameters parameters = new Parameters();

    public ExitStatusJob() {
        this.data = new Data(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData != null) {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) jobData.get("parameters"),
                    this.parameters,
                    this.getName(),
                    null,
                    progress);
        }

        Integer errorRisk =
                JobUtils.parseAlertRisk(parameters.getErrorLevel(), this.getName(), progress);
        Integer warnRisk =
                JobUtils.parseAlertRisk(parameters.getWarnLevel(), this.getName(), progress);
        if (warnRisk != null && errorRisk != null && warnRisk > errorRisk) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.exitstatus.error.badlevels",
                            parameters.getErrorLevel(),
                            parameters.getWarnLevel()));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {}

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        Integer errorRisk = JobUtils.parseAlertRisk(parameters.getErrorLevel());
        Integer warnRisk = JobUtils.parseAlertRisk(parameters.getWarnLevel());
        boolean warningRaised = false;

        try {
            for (JobResultData data : progress.getAllJobResultData()) {
                for (Alert alert : data.getAllAlertData()) {
                    if (alert.getConfidence() == Alert.CONFIDENCE_FALSE_POSITIVE) {
                        continue;
                    }
                    if (errorRisk != null && errorRisk <= alert.getRisk()) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.exitstatus.alert", parameters.getErrorLevel()));
                        return;
                    }
                    if (!warningRaised && warnRisk != null && warnRisk <= alert.getRisk()) {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.exitstatus.alert", parameters.getWarnLevel()));
                        warningRaised = true;
                    }
                }
            }
        } finally {
            // Set the exit value, if configured
            if (progress.hasErrors()) {
                if (parameters.getErrorExitValue() != null) {
                    ExtensionAutomation.setExitOverride(parameters.getErrorExitValue());
                }
            } else if (progress.hasWarnings()) {
                if (parameters.getWarnExitValue() != null) {
                    ExtensionAutomation.setExitOverride(parameters.getWarnExitValue());
                }
            } else {
                if (parameters.getOkExitValue() != null) {
                    ExtensionAutomation.setExitOverride(parameters.getOkExitValue());
                }
            }
        }
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.RUN_LAST;
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
        new ExitStatusJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.exitstatus.summary",
                this.getData().getParameters().getErrorLevel(),
                this.getData().getParameters().getWarnLevel());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return this.parameters;
    }

    @Getter
    public static class Data extends JobData {
        private final Parameters parameters;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private String errorLevel = "";
        private String warnLevel = "";
        private Integer okExitValue;
        private Integer warnExitValue;
        private Integer errorExitValue;
    }
}
