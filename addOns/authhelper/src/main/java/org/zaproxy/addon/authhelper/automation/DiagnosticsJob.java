/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;

public class DiagnosticsJob extends AutomationJob {

    public static final String JOB_NAME = "diagnostics";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/authhelper/resources/";

    private static final Map<AutomationPlan, AuthenticationDiagnostics> recordings =
            new ConcurrentHashMap<>();

    private final Parameters parameters = new Parameters();
    private final Data data;

    public DiagnosticsJob() {
        this.data = new Data(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                parameters,
                getName(),
                null,
                progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do.
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put("enabled", "false");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        AutomationPlan plan = env.getPlan();
        if (parameters.isEnabled()) {
            if (recordings.containsKey(plan)) {
                progress.warn(
                        Constant.messages.getString(
                                "authhelper.automation.diagnostics.warn.alreadyenabled",
                                getName()));
                return;
            }
            recordings.put(
                    plan,
                    new AuthenticationDiagnostics(
                            true,
                            Constant.messages.getString(
                                    "authhelper.automation.diagnostics.authmethod"),
                            env.getDefaultContext().getName(),
                            ""));
            progress.info(
                    Constant.messages.getString(
                            "authhelper.automation.diagnostics.info.enabled", getName()));
        } else if (stopRecording(plan)) {
            progress.info(
                    Constant.messages.getString(
                            "authhelper.automation.diagnostics.info.disabled", getName()));
        } else {
            progress.warn(
                    Constant.messages.getString(
                            "authhelper.automation.diagnostics.warn.notenabled", getName()));
        }
    }

    @Override
    public void planFinished() {
        stopRecording(getPlan());
    }

    private static boolean stopRecording(AutomationPlan plan) {
        if (plan == null) {
            return false;
        }
        AuthenticationDiagnostics recording = recordings.remove(plan);
        if (recording == null) {
            return false;
        }
        recording.recordStep(Constant.messages.getString("authhelper.automation.diagnostics.step"));
        recording.close();
        return true;
    }

    @Override
    public void showDialog() {
        new DiagnosticsJobDialog(this).setVisible(true);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(JOB_NAME + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(JOB_NAME + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try (InputStream in = DiagnosticsJob.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "authhelper.automation.diagnostics.error.nofile",
                            RESOURCES_DIR + name));
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
    public Parameters getParameters() {
        return parameters;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "authhelper.automation.diagnostics.summary", parameters.isEnabled());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Getter
    @Setter
    public static class Data extends JobData {
        private Parameters parameters;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private boolean enabled;
    }
}
