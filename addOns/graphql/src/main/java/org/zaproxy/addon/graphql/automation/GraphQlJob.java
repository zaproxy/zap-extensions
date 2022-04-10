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
package org.zaproxy.addon.graphql.automation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.graphql.ExtensionGraphQl;
import org.zaproxy.addon.graphql.GraphQlParser;
import org.zaproxy.addon.graphql.HistoryPersister;

public class GraphQlJob extends AutomationJob {

    private static final String JOB_NAME = "graphql";
    private static final String OPTIONS_METHOD_NAME = "getParam";

    private static final String PARAM_ENDPOINT = "endpoint";
    private static final String PARAM_SCHEMA_URL = "schemaUrl";
    private static final String PARAM_SCHEMA_FILE = "schemaFile";

    private static final String RESOURCES_DIR = "/org/zaproxy/addon/graphql/resources/";

    private Data data;
    private Parameters parameters = new Parameters();

    public GraphQlJob() {
        this.data = new Data(this, parameters);
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
        JobUtils.applyObjectToObject(
                this.parameters,
                JobUtils.getJobOptions(this, progress),
                this.getName(),
                new String[] {PARAM_ENDPOINT, PARAM_SCHEMA_URL, PARAM_SCHEMA_FILE},
                progress,
                this.getPlan().getEnv());
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_ENDPOINT, "");
        map.put(PARAM_SCHEMA_URL, "");
        map.put(PARAM_SCHEMA_FILE, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        String endpoint = this.getParameters().getEndpoint();
        if (endpoint == null || endpoint.isEmpty()) {
            progress.info(Constant.messages.getString("graphql.info.emptyendurl"));
            return;
        }

        try {
            String endpointUrl = env.replaceVars(endpoint);
            GraphQlParser parser =
                    new GraphQlParser(endpointUrl, HttpSender.MANUAL_REQUEST_INITIATOR, true);
            parser.addRequesterListener(new HistoryPersister());

            String schemaFile = this.getParameters().getSchemaFile();
            String schemaUrl = this.getParameters().getSchemaUrl();

            if (schemaFile != null && !schemaFile.isEmpty()) {
                String file = env.replaceVars(schemaFile);
                progress.info(
                        Constant.messages.getString(
                                "graphql.automation.info.import.file", file, endpointUrl));
                parser.importFile(file);
            } else if (schemaUrl != null && !schemaUrl.isEmpty()) {
                String url = env.replaceVars(schemaUrl);
                progress.info(
                        Constant.messages.getString(
                                "graphql.automation.info.import.url", url, endpointUrl));
                parser.importUrl(url);
            } else {
                progress.info(
                        Constant.messages.getString(
                                "graphql.automation.info.import.introspect", endpointUrl));
                parser.introspect();
            }
        } catch (IOException e) {
            progress.error(Constant.messages.getString("graphql.automation.error", e.getMessage()));
        }
    }

    @Override
    public String getTemplateDataMin() {
        return getResourceAsString(getName() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return getResourceAsString(getName() + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    GraphQlJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "openapi.automation.error.nofile", RESOURCES_DIR + name));
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
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionGraphQl.class);
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public void showDialog() {
        new GraphQlJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "graphql.automation.dialog.summary",
                JobUtils.unBox(this.getParameters().getSchemaUrl(), "''"),
                JobUtils.unBox(this.getParameters().getSchemaFile(), "''"));
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
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
    }

    public static class Parameters extends AutomationData {
        private String endpoint;
        private String schemaUrl;
        private String schemaFile;
        private Integer maxQueryDepth;
        private Boolean lenientMaxQueryDepthEnabled;
        private Integer maxAdditionalQueryDepth;
        private Integer maxArgsDepth;
        private Boolean optionalArgsEnabled;
        private String argsType;
        private String querySplitType;
        private String requestMethod;

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getSchemaUrl() {
            return schemaUrl;
        }

        public void setSchemaUrl(String schemaUrl) {
            this.schemaUrl = schemaUrl;
        }

        public String getSchemaFile() {
            return schemaFile;
        }

        public void setSchemaFile(String schemaFile) {
            this.schemaFile = schemaFile;
        }

        public Integer getMaxQueryDepth() {
            return maxQueryDepth;
        }

        public void setMaxQueryDepth(Integer maxQueryDepth) {
            this.maxQueryDepth = maxQueryDepth;
        }

        public Boolean getLenientMaxQueryDepthEnabled() {
            return lenientMaxQueryDepthEnabled;
        }

        public void setLenientMaxQueryDepthEnabled(Boolean lenientMaxQueryDepthEnabled) {
            this.lenientMaxQueryDepthEnabled = lenientMaxQueryDepthEnabled;
        }

        public Integer getMaxAdditionalQueryDepth() {
            return maxAdditionalQueryDepth;
        }

        public void setMaxAdditionalQueryDepth(Integer maxAdditionalQueryDepth) {
            this.maxAdditionalQueryDepth = maxAdditionalQueryDepth;
        }

        public Integer getMaxArgsDepth() {
            return maxArgsDepth;
        }

        public void setMaxArgsDepth(Integer maxArgsDepth) {
            this.maxArgsDepth = maxArgsDepth;
        }

        public Boolean getOptionalArgsEnabled() {
            return optionalArgsEnabled;
        }

        public void setOptionalArgsEnabled(Boolean optionalArgsEnabled) {
            this.optionalArgsEnabled = optionalArgsEnabled;
        }

        public String getArgsType() {
            return argsType;
        }

        public void setArgsType(String argsType) {
            this.argsType = argsType;
        }

        public String getQuerySplitType() {
            return querySplitType;
        }

        public void setQuerySplitType(String querySplitType) {
            this.querySplitType = querySplitType;
        }

        public String getRequestMethod() {
            return requestMethod;
        }

        public void setRequestMethod(String requestMethod) {
            this.requestMethod = requestMethod;
        }
    }
}
