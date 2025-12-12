/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.insights.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.addon.insights.InsightListener;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.internal.InsightsParam;

public class InsightsJob extends AutomationJob implements InsightListener {

    private static final String JOB_NAME = "insights";
    private static final String RESOURCES_DIR =
            "/org/zaproxy/zap/extension/alertFilters/resources/";

    private static final String OPTIONS_METHOD_NAME = "getParam";

    private ExtensionInsights extInsights;

    private Data data;

    public InsightsJob() {
        data = new Data(this);
    }

    private ExtensionInsights getExtInsights() {
        if (extInsights == null) {
            extInsights =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionInsights.class);
        }
        return extInsights;
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
                            params, this.data.parameters, this.getName(), null, progress);
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.element.unknown", this.getName(), key));
                    break;
            }
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {}

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        this.getExtInsights().addInsightListener(this);
        this.getExtInsights().setDisableExit(true);
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getName() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getName() + "-max.yaml");
    }

    private String getResourceAsString(String name) {
        try (InputStream in = ExtensionInsights.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString("automation.error.nofile", RESOURCES_DIR + name));
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
        return this.getExtInsights();
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public void showDialog() {
        new InsightsJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString("insights.automation.dialog.summary");
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return getData().getParameters();
    }

    public static class Data extends JobData {
        private Parameters parameters = new Parameters();

        public Data(AutomationJob job) {
            super(job);
        }

        public Parameters getParameters() {
            return parameters;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {
        private int messagesLowThreshold = InsightsParam.DEFAULT_MSG_LOW_THRESHOLD;
        private int messagesHighThreshold = InsightsParam.DEFAULT_MSG_HIGH_THRESHOLD;
        private int memoryLowThreshold = InsightsParam.DEFAULT_MEM_LOW_THRESHOLD;
        private int memoryHighThreshold = InsightsParam.DEFAULT_MEM_HIGH_THRESHOLD;
        private int slowResponse = InsightsParam.DEFAULT_SLOW_RESPONSE;
        private boolean exitAutoOnHigh = InsightsParam.DEFAULT_EXIT_AUTO_ON_HIGH;
    }

    @Override
    public void recordInsight(Insight ins) {
        if (ins.getLevel().equals(Insight.Level.HIGH) && this.getParameters().isExitAutoOnHigh()) {
            this.getEnv()
                    .getPlan()
                    .getProgress()
                    .warn(Constant.messages.getString("insights.automation.stopplan"));
            this.getEnv().getPlan().stopPlan(false);
        }
    }

    @Override
    public void planFinished() {
        this.getExtInsights().setDisableExit(false);
        this.getExtInsights().removeInsightListener(this);
    }
}
