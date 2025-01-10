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
package org.zaproxy.addon.exim.automation;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.exim.ExporterOptions;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExporterOptions.Type;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.addon.exim.ExtensionExim;

public class ExportJob extends AutomationJob {

    private static final String JOB_NAME = "export";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/exim/resources/";

    private static final String PARAM_CONTEXT = "context";
    private static final String PARAM_TYPE = "type";
    private static final String PARAM_SOURCE = "source";
    private static final String PARAM_FILE_NAME = "fileName";

    private final ExtensionExim extension;

    private Parameters parameters = new Parameters();
    private Data data;

    public ExportJob(ExtensionExim extension) {
        this.extension = extension;
        this.data = new Data(this, parameters);
    }

    @Override
    public AutomationJob newJob() throws AutomationJobException {
        return new ExportJob(extension);
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

        // Check for invalid combinations
        if (Source.SITESTREE.equals(this.parameters.getSource())
                && !Type.YAML.equals(this.parameters.getType())) {
            progress.error(
                    Constant.messages.getString(
                            "exim.automation.export.error.sitestree.type",
                            this.getName(),
                            this.parameters.getType()));
        } else if (!Source.SITESTREE.equals(this.parameters.getSource())
                && Type.YAML.equals(this.parameters.getType())) {
            progress.error(
                    Constant.messages.getString(
                            "exim.automation.export.error.messages.type",
                            this.getName(),
                            this.parameters.getSource()));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Nothing to do
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_CONTEXT, "");
        map.put(PARAM_TYPE, "");
        map.put(PARAM_SOURCE, "");
        map.put(PARAM_FILE_NAME, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        String fileName = getParameters().getFileName();
        if (StringUtils.isEmpty(fileName)) {
            progress.info(Constant.messages.getString("exim.automation.export.nofile", getName()));
            return;
        }

        ContextWrapper contextWrapper = env.getContextWrapper(getParameters().getContext());
        if (contextWrapper == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.context.unknown", getParameters().getContext()));
            return;
        }

        Path path = JobUtils.getFile(fileName, getPlan()).toPath();

        ExporterOptions options =
                ExporterOptions.builder()
                        .setContext(contextWrapper.getContext())
                        .setOutputFile(path)
                        .setType(getParameters().getType())
                        .setSource(getParameters().getSource())
                        .build();

        ExporterResult result = extension.getExporter().export(options);
        progress.info(
                Constant.messages.getString(
                        "exim.automation.export.exportcount",
                        getName(),
                        result.getCount(),
                        path.toAbsolutePath()));
        result.getErrors()
                .forEach(
                        error ->
                                progress.error(
                                        Constant.messages.getString(
                                                "exim.automation.export.error", getName(), error)));
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getType() + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    ExportJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "exim.automation.error.noresourcefile", RESOURCES_DIR + name));
        }
        return "";
    }

    @Override
    public Order getOrder() {
        return Order.AFTER_ATTACK;
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
        new ExportJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "exim.automation.export.dialog.summary",
                getParameters().getType(),
                getParameters().getSource(),
                JobUtils.unBox(getParameters().getFileName(), "''"));
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
        private String context = "";
        private Type type = Type.HAR;
        private Source source = Source.HISTORY;
        private String fileName;
    }
}
