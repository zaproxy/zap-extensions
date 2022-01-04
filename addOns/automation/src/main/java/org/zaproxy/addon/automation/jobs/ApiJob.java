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
package org.zaproxy.addon.automation.jobs;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.ApiJobDialog;
import org.zaproxy.zap.extension.api.API;

public class ApiJob extends AutomationJob {

    public static final String JOB_NAME = "api";
    private final Logger LOGGER = LogManager.getLogger(this.getClass());
    private Data data;
    private Parameters parameters = new Parameters();
    private HttpSender httpSender;

    public ApiJob() {
        this.data = new Data(this, parameters);

        this.httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        applyParameters(progress);
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
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

        this.data.apiParameters.clear();

        if (jobData.get("apiParameters") == null) {
            return;
        }

        ArrayList<?> apiParameterObjects = (ArrayList<?>) jobData.get("apiParameters");
        for (Object apiParameterObject : apiParameterObjects) {
            ApiParameter apiParameter = new ApiParameter();
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) apiParameterObject,
                    apiParameter,
                    this.getName(),
                    null,
                    progress);
            this.data.apiParameters.add(apiParameter);
        }
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        try {
            URI uri = new URI(getApiUrl(), true);
            HttpRequestHeader reqHeader =
                    new HttpRequestHeader(HttpRequestHeader.GET, uri, HttpHeader.HTTP11);
            HttpMessage apiMsg = new HttpMessage(reqHeader);
            TreeSet<HtmlParameter> queryParams = new TreeSet<>();
            for (ApiParameter apiParameter : data.getApiParameters()) {
                queryParams.add(
                        new HtmlParameter(
                                HtmlParameter.Type.url,
                                apiParameter.getName(),
                                apiParameter.getValue()));
            }
            apiMsg.setGetParams(queryParams);
            progress.info("Send API request");
            progress.info(apiMsg.getRequestHeader().getURI().toString());

            queryParams.add(
                    new HtmlParameter(HtmlParameter.Type.url, "apikey", parameters.getApiKey()));
            apiMsg.setGetParams(queryParams);

            // ToDo: Maybe possible with handleApiRequest to circumvent network stack?
            this.httpSender.sendAndReceive(apiMsg);
            progress.info("Received API response");
            progress.info(apiMsg.getResponseBody().toString());
        } catch (Exception e) {
            LOGGER.error(e);
            progress.error(e.toString());
        }
    }

    private String getApiUrl() {
        API.Format format = API.Format.JSON;
        if (parameters.getApiOutputFormat() != null) {
            format = API.Format.valueOf(parameters.getApiOutputFormat());
        }

        API.RequestType requestType = API.RequestType.view;
        if (parameters.getApiRequestType() != null) {
            requestType = API.RequestType.valueOf(parameters.getApiRequestType());
        }

        return API.getInstance()
                .getBaseURL(
                        format,
                        parameters.getApiPrefix(),
                        requestType,
                        parameters.getApiName(),
                        false);
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.CONFIGS;
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
        new ApiJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.api.summary",
                getApiUrl(),
                this.getData().getApiParameters().size());
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return this.parameters;
    }

    public static class Data extends JobData {
        private Parameters parameters;
        private List<ApiParameter> apiParameters = new ArrayList<>();

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public List<ApiParameter> getApiParameters() {
            return apiParameters;
        }

        public void setApiParameters(List<ApiParameter> apiParameters) {
            this.apiParameters = apiParameters;
        }
    }

    public static class Parameters extends AutomationData {
        private String apiOutputFormat = API.Format.JSON.toString();
        private String apiPrefix;
        private String apiRequestType = API.RequestType.view.toString();
        private String apiName;
        private String apiKey;

        public String getApiOutputFormat() {
            return apiOutputFormat;
        }

        public void setApiOutputFormat(String apiOutputFormat) {
            this.apiOutputFormat = apiOutputFormat;
        }

        public String getApiPrefix() {
            return apiPrefix;
        }

        public void setApiPrefix(String apiPrefix) {
            this.apiPrefix = apiPrefix;
        }

        public String getApiRequestType() {
            return apiRequestType;
        }

        public void setApiRequestType(String apiRequestType) {
            this.apiRequestType = apiRequestType;
        }

        public String getApiName() {
            return apiName;
        }

        public void setApiName(String apiName) {
            this.apiName = apiName;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }
    }

    public static class ApiParameter extends AutomationData {
        private String name;
        private String value;

        public ApiParameter() {}

        public ApiParameter(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public ApiParameter copy() {
            return new ApiParameter(name, value);
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
