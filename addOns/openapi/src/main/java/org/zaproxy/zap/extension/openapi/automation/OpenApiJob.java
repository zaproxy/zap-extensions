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
package org.zaproxy.zap.extension.openapi.automation;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.io.IOUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.extension.openapi.OpenApiResults;

public class OpenApiJob extends AutomationJob {

    private static final String JOB_NAME = "openapi";
    private static final String RESOURCES_DIR = "/org/zaproxy/zap/extension/openapi/resources/";

    private static final String PARAM_API_URL = "apiUrl";
    private static final String PARAM_API_FILE = "apiFile";
    private static final String PARAM_TARGET_URL = "targetUrl";

    private ExtensionOpenApi extOpenApi;

    private String apiUrl;
    private String apiFile;
    private String targetUrl;

    public OpenApiJob() {}

    private ExtensionOpenApi getExtOpenApi() {
        if (extOpenApi == null) {
            extOpenApi =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionOpenApi.class);
        }
        return extOpenApi;
    }

    public boolean applyCustomParameter(String name, String value) {
        switch (name) {
            case PARAM_API_URL:
                apiUrl = value;
                return true;
            case PARAM_API_FILE:
                apiFile = value;
                return true;
            case PARAM_TARGET_URL:
                targetUrl = value;
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
        map.put(PARAM_API_URL, "");
        map.put(PARAM_API_FILE, "");
        map.put(PARAM_TARGET_URL, "");
        return map;
    }

    @Override
    public void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress) {

        if (this.apiFile != null && this.apiFile.length() > 0) {
            File file = new File(apiFile);
            if (file.exists() && file.canRead()) {
                OpenApiResults results =
                        getExtOpenApi().importOpenApiDefinitionV2(file, targetUrl, false, -1);
                List<String> errors = results.getErrors();
                if (errors != null && errors.size() > 0) {
                    for (String error : errors) {
                        progress.error(
                                Constant.messages.getString(
                                        "openapi.automation.error.misc", this.getName(), error));
                    }
                }
                progress.info(
                        Constant.messages.getString(
                                "openapi.automation.info.urlsadded",
                                this.getName(),
                                results.getHistoryReferences().size()));
            } else {
                progress.error(
                        Constant.messages.getString(
                                "openapi.automation.error.file", this.getName(), this.apiFile));
            }
        }
        if (this.apiUrl != null && this.apiUrl.length() > 0) {
            try {
                URI uri = new URI(this.apiUrl, true);
                OpenApiResults results =
                        getExtOpenApi().importOpenApiDefinitionV2(uri, targetUrl, false, -1);
                List<String> errors = results.getErrors();
                if (errors != null && errors.size() > 0) {
                    for (String error : errors) {
                        progress.error(
                                Constant.messages.getString(
                                        "openapi.automation.error.misc", this.getName(), error));
                    }
                }
                progress.info(
                        Constant.messages.getString(
                                "openapi.automation.info.urlsadded",
                                this.getName(),
                                results.getHistoryReferences().size()));
            } catch (Exception e) {
                progress.error(
                        Constant.messages.getString(
                                "openapi.automation.error.url", this.getName(), this.apiUrl));
            }
        }
    }

    public String getTemplateDataMin() {
        return getResourceAsString(this.getType() + "-min.yaml");
    }

    public String getTemplateDataMax() {
        return getResourceAsString(this.getType() + "-max.yaml");
    }

    private static String getResourceAsString(String name) {
        try {
            return IOUtils.toString(
                    OpenApiJob.class.getResourceAsStream(RESOURCES_DIR + name),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "openapi.automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    // For Unit Tests
    protected String getApiFile() {
        return apiFile;
    }

    // For Unit Tests
    protected String getApiUrl() {
        return apiUrl;
    }

    // For Unit Tests
    protected String getTargetUrl() {
        return targetUrl;
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
}
