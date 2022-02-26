/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.addon.exim.har.HarImporter;
import org.zaproxy.addon.exim.log.LogsImporter;
import org.zaproxy.addon.exim.urls.UrlsImporter;

public class ImportJob extends AutomationJob {

    private static final String JOB_NAME = "import";
    private static final String RESOURCES_DIR = "/org/zaproxy/addon/exim/resources/";

    private static final String PARAM_TYPE = "type";
    private static final String PARAM_FILE_NAME = "fileName";

    private ExtensionExim extExim;

    private Parameters parameters = new Parameters();
    private Data data;

    public ImportJob() {
        this.data = new Data(this, parameters);
    }

    private ExtensionExim getExtExim() {
        if (extExim == null) {
            extExim = Control.getSingleton().getExtensionLoader().getExtension(ExtensionExim.class);
        }
        return extExim;
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
        map.put(PARAM_TYPE, "");
        map.put(PARAM_FILE_NAME, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        String type = this.getParameters().getType();
        String fileName = this.getParameters().getFileName();

        if (!StringUtils.isEmpty(fileName)) {
            File file = new File(fileName);
            if (file.exists() && file.canRead()) {
                if (type.equalsIgnoreCase(TypeOption.HAR.name())) {
                    HarImporter harImporter = new HarImporter(file);
                    if (!harImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        TypeOption.HAR));
                    }
                } else if (type.equalsIgnoreCase(TypeOption.MODSEC2.name())) {
                    LogsImporter logsImporter =
                            new LogsImporter(file, LogsImporter.LogType.MOD_SECURITY_2);
                    if (!logsImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        TypeOption.MODSEC2));
                    }
                } else if (type.equalsIgnoreCase(TypeOption.URL.name())) {
                    UrlsImporter urlsImporter = new UrlsImporter(file);
                    if (!urlsImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        TypeOption.URL));
                    }
                } else if (type.equalsIgnoreCase(TypeOption.ZAP_MESSAGES.name())) {
                    LogsImporter zapImporter = new LogsImporter(file, LogsImporter.LogType.ZAP);
                    if (!zapImporter.isSuccess()) {
                        progress.error(
                                Constant.messages.getString(
                                        "exim.automation.import.error",
                                        file.getAbsolutePath(),
                                        TypeOption.ZAP_MESSAGES));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "exim.automation.import.error.type", this.getName(), type));
                }
            } else {
                progress.error(
                        Constant.messages.getString(
                                "exim.automation.import.error.file", this.getName(), fileName));
            }
        }
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
                    ImportJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "exim.automation.import.error.nofile", RESOURCES_DIR + name));
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
        new ImportJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "exim.automation.import.dialog.summary",
                JobUtils.unBox(this.getParameters().getType(), "''"),
                JobUtils.unBox(this.getParameters().getFileName(), "''"));
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

    public static class Parameters extends AutomationData {
        private String type;
        private String fileName;

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getFileName() {
            return fileName;
        }

        public void setFileName(String fileName) {
            this.fileName = fileName;
        }
    }

    public enum TypeOption {
        HAR,
        MODSEC2,
        URL,
        ZAP_MESSAGES;

        @Override
        public String toString() {
            switch (this) {
                case HAR:
                    return Constant.messages.getString("exim.options.value.type.har");
                case MODSEC2:
                    return Constant.messages.getString("exim.options.value.type.modsec2");
                case URL:
                    return Constant.messages.getString("exim.options.value.type.url");
                case ZAP_MESSAGES:
                    return Constant.messages.getString("exim.options.value.type.zapmessages");
                default:
                    return "";
            }
        }
    }
}
