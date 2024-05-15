/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.automation;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.postman.PostmanParser;

public class PostmanJob extends AutomationJob {

    private static final String JOB_NAME = "postman";

    private static final String PARAM_COLLECTION_URL = "collectionUrl";
    private static final String PARAM_COLLECTION_FILE = "collectionFile";
    private static final String PARAM_VARS = "variables";

    private Parameters parameters = new Parameters();
    private Data data;

    public PostmanJob() {
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
        // Nothing to do.
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_COLLECTION_URL, "");
        map.put(PARAM_COLLECTION_FILE, "");
        map.put(PARAM_VARS, "");
        return map;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        String collectionFile = this.getParameters().getCollectionFile();
        String collectionStr = this.getParameters().getCollectionUrl();
        String variables = this.getParameters().getVariables();

        PostmanParser parser = new PostmanParser();

        if (!StringUtils.isEmpty(collectionFile)) {
            File file = JobUtils.getFile(collectionFile, getPlan());

            try {
                parser.importFromFile(file.getAbsolutePath(), variables, false);
            } catch (IOException e) {
                progress.error(
                        Constant.messages.getString("postman.automation.error", e.getMessage()));
                return;
            }
        }

        if (!StringUtils.isEmpty(collectionStr)) {
            String collectionUrl = env.replaceVars(collectionStr);

            try {
                new URL(collectionUrl).toURI();
                new URI(collectionUrl, true);

                parser.importFromUrl(collectionUrl, variables, false);
            } catch (IOException | URISyntaxException e) {
                progress.error(
                        Constant.messages.getString("postman.automation.error", e.getMessage()));
            }
        }
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
                    PostmanJob.class.getResourceAsStream(name), StandardCharsets.UTF_8);
        } catch (IOException ignore) {
            // Bundled files.
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
        new PostmanJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "postman.automation.dialog.summary",
                JobUtils.unBox(this.getParameters().getCollectionUrl(), "''"),
                JobUtils.unBox(this.getParameters().getCollectionFile(), "''"));
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
        private String collectionFile;
        private String collectionUrl;
        private String variables;

        public String getCollectionFile() {
            return collectionFile;
        }

        public void setCollectionFile(String collectionFile) {
            this.collectionFile = collectionFile;
        }

        public String getCollectionUrl() {
            return collectionUrl;
        }

        public void setCollectionUrl(String collectionUrl) {
            this.collectionUrl = collectionUrl;
        }

        public String getVariables() {
            return variables;
        }

        public void setVariables(String variables) {
            this.variables = variables;
        }
    }
}
