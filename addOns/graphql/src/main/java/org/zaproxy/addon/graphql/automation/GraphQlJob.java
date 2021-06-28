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
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
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

    private String endpoint;
    private String schemaUrl;
    private String schemaFile;

    public GraphQlJob() {}

    @Override
    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_ENDPOINT:
                endpoint = value;
                return true;
            case PARAM_SCHEMA_URL:
                schemaUrl = value;
                return true;
            case PARAM_SCHEMA_FILE:
                schemaFile = value;
                return true;
            default:
                // Ignore
                break;
        }
        return false;
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
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        if (endpoint == null || endpoint.isEmpty()) {
            progress.info(Constant.messages.getString("graphql.info.emptyendurl"));
            return;
        }

        try {
            GraphQlParser parser =
                    new GraphQlParser(endpoint, HttpSender.MANUAL_REQUEST_INITIATOR, true);
            parser.addRequesterListener(new HistoryPersister());

            if (schemaFile != null && !schemaFile.isEmpty()) {
                progress.info(Constant.messages.getString("graphql.automation.info.import.file"));
                parser.importFile(schemaFile);
            } else if (schemaUrl != null && !schemaUrl.isEmpty()) {
                progress.info(Constant.messages.getString("graphql.automation.info.import.url"));
                parser.importUrl(schemaUrl);
            } else {
                progress.info(
                        Constant.messages.getString("graphql.automation.info.import.introspect"));
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

    // For Unit Tests
    protected String getEndpoint() {
        return endpoint;
    }

    // For Unit Tests
    protected String getSchemaFile() {
        return schemaFile;
    }

    // For Unit Tests
    protected String getSchemaUrl() {
        return schemaUrl;
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
}
