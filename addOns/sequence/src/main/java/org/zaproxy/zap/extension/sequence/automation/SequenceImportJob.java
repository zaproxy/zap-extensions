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
package org.zaproxy.zap.extension.sequence.automation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.addon.exim.ImporterOptions;
import org.zaproxy.addon.exim.ImporterResult;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.zest.CreateScriptOptions;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.utils.Stats;

public class SequenceImportJob extends AutomationJob {

    private static final String JOB_NAME = "sequence-import";
    private static final String RESOURCES_DIR = "/org/zaproxy/zap/extension/sequence/resources/";

    private static final String PARAM_NAME = "name";
    private static final String PARAM_PATH = "path";
    private static final String PARAM_ASSERT_CODE = "assertCode";
    private static final String PARAM_ASSERT_LENGTH = "assertLength";

    private final ScriptType scriptType;
    private final ExtensionExim exim;
    private final ExtensionZest zest;

    private Parameters parameters = new Parameters();
    private Data data;

    public SequenceImportJob(ScriptType scriptType, ExtensionExim exim, ExtensionZest zest) {
        this.scriptType = scriptType;
        this.exim = exim;
        this.zest = zest;
        this.data = new Data(this, parameters);
    }

    @Override
    public AutomationJob newJob() throws AutomationJobException {
        return new SequenceImportJob(scriptType, exim, zest);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData == null) {
            return;
        }
        JobUtils.applyParamsToObject(
                (LinkedHashMap<?, ?>) jobData.get("parameters"),
                this.parameters,
                this.getName(),
                null,
                progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_NAME, "");
        map.put(PARAM_PATH, "");
        map.put(PARAM_ASSERT_CODE, "");
        map.put(PARAM_ASSERT_LENGTH, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        String path = getParameters().getPath();
        if (StringUtils.isBlank(path)) {
            return;
        }

        Path file = JobUtils.getFile(path, getPlan()).toPath();
        String name = getParameters().getName();
        if (StringUtils.isBlank(name)) {
            name = file.getFileName().toString().replaceFirst("(?i)\\.har$", "");
        }

        List<HttpMessage> messages = new ArrayList<>();
        ImporterResult result =
                exim.getImporter()
                        .apply(
                                ImporterOptions.builder()
                                        .setInputFile(file)
                                        .setMessageHandler(messages::add)
                                        .build());

        result.getErrors()
                .forEach(
                        error -> {
                            progress.error(
                                    Constant.messages.getString(
                                            "sequence.automation.import.error", getName(), error));
                            Stats.incCounter(
                                    ExtensionSequenceAutomation.STATS_PREFIX + "import.error");
                        });
        if (result.getCount() == 0) {
            progress.warn(
                    Constant.messages.getString(
                            "sequence.automation.import.nomessages", getName(), result.getCount()));
            Stats.incCounter(ExtensionSequenceAutomation.STATS_PREFIX + "import.nomessages");
            return;
        }

        try {
            zest.createScript(name, scriptType, messages, createScriptOptions(parameters));
            progress.info(
                    Constant.messages.getString(
                            "sequence.automation.import.sequencecreated",
                            getName(),
                            result.getCount()));
            Stats.incCounter(ExtensionSequenceAutomation.STATS_PREFIX + "import");
            Stats.incCounter(
                    ExtensionSequenceAutomation.STATS_PREFIX + "import.messages",
                    result.getCount());
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "sequence.automation.import.script.error", getName(), e.getMessage()));
            Stats.incCounter(ExtensionSequenceAutomation.STATS_PREFIX + "import.script.error");
        }
    }

    private static CreateScriptOptions createScriptOptions(Parameters parameters) {
        CreateScriptOptions.Builder builder =
                CreateScriptOptions.builder()
                        .setIncludeResponses(CreateScriptOptions.IncludeResponses.ALWAYS)
                        .setAddStatusAssertion(JobUtils.unBox(parameters.getAssertCode()));
        Integer assertLengthValue = parameters.getAssertLength();
        if (assertLengthValue != null) {
            builder.setAddLengthAssertion(true).setLengthApprox(assertLengthValue);
        }
        return builder.build();
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(this.getType() + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    SequenceImportJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "sequence.automation.error.noresourcefile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.EXPLORE;
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
    public void showDialog() {
        new SequenceImportJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "sequence.automation.import.summary",
                JobUtils.unBox(this.getParameters().getName(), "''"),
                JobUtils.unBox(this.getParameters().getPath(), "''"));
    }

    @Override
    public Data getData() {
        return data;
    }

    public static class Data extends JobData {

        private Parameters parameters;

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public void setParameters(Parameters parameters) {
            this.parameters = parameters;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {

        private String name = "";
        private String path;
        private Boolean assertCode = false;
        private Integer assertLength;

        public void setAssertLength(Integer assertLength) {
            this.assertLength = valueInRange(assertLength, 0, 100);
        }

        private static Integer valueInRange(Integer value, int min, int max) {
            if (value == null) {
                return null;
            }
            if (value > max) {
                return max;
            }
            if (value < min) {
                return min;
            }
            return value;
        }
    }
}
