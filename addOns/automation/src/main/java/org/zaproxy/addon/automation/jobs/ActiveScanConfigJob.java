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
package org.zaproxy.addon.automation.jobs;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationJobException;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.ActiveScanConfigJobDialog;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;

public class ActiveScanConfigJob extends AutomationJob {
    private static final ObjectMapper OBJECT_MAPPER =
            JsonMapper.builder()
                    .defaultPropertyInclusion(
                            JsonInclude.Value.construct(
                                    JsonInclude.Include.NON_DEFAULT,
                                    JsonInclude.Include.NON_DEFAULT))
                    .build()
                    .findAndRegisterModules();

    public static final String JOB_NAME = "activeScan-config";
    private static final String OPTIONS_METHOD_NAME = "getScannerParam";

    private static final Logger LOGGER = LogManager.getLogger(ActiveScanConfigJob.class);

    private ExtensionActiveScan ascan;

    private Parameters parameters = new Parameters();
    private InputVectors inputVectors = new InputVectors();
    private Data data;

    public ActiveScanConfigJob(ExtensionActiveScan ascan) {
        data = new Data(this, parameters, inputVectors);

        this.ascan = ascan;
    }

    @Override
    public AutomationJob newJob() throws AutomationJobException {
        return new ActiveScanConfigJob(ascan);
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
                    updateValue(data.getParameters(), jobData, key, progress);
                    break;

                case "inputVectors":
                    updateValue(data.getInputVectors(), jobData, key, progress);
                    break;

                case "excludePaths":
                    data.setExcludePaths(
                            JobUtils.verifyRegexes(jobData.get(key), key.toString(), progress));
                    break;

                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.element.unknown", this.getName(), key));

                    break;
            }
        }
    }

    private void updateValue(
            Object value, Map<?, ?> jobData, Object key, AutomationProgress progress) {
        try {
            OBJECT_MAPPER.updateValue(value, jobData.get(key));
        } catch (JsonMappingException e) {
            progress.error(
                    Constant.messages.getString(
                            "automation.dialog.ascanconfig.error.field",
                            getName(),
                            key,
                            e.getMessage()));
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        ScannerParam params = (ScannerParam) JobUtils.getJobOptions(this, progress);
        JobUtils.applyObjectToObject(
                parameters, params, getName(), new String[] {}, progress, getEnv());

        BitSet targetParamsInjectable = fromInt(ScannerParam.TARGET_INJECTABLE_DEFAULT);
        BitSet targetParamsEnabledRPC = fromInt(ScannerParam.TARGET_ENABLED_RPC_DEFAULT);

        InputVectors.UrlQueryStringAndDataDrivenNodes queryOptions =
                inputVectors.getUrlQueryStringAndDataDrivenNodes();
        if (queryOptions != null) {
            targetParamsInjectable.set(0, queryOptions.isEnabled());
            params.setAddQueryParam(queryOptions.isAddParam());
            targetParamsEnabledRPC.set(4, queryOptions.isOdata());
        }

        InputVectors.PostData postOptions = inputVectors.getPostData();
        if (postOptions != null) {
            targetParamsInjectable.set(1, postOptions.isEnabled());
            targetParamsEnabledRPC.set(0, postOptions.isMultiPartFormData());
            targetParamsEnabledRPC.set(1, postOptions.isXml());

            InputVectors.PostData.Json jsonOptions = postOptions.getJson();
            if (jsonOptions != null) {
                targetParamsEnabledRPC.set(2, jsonOptions.isEnabled());
                params.setScanNullJsonValues(jsonOptions.isScanNullValues());
            }

            targetParamsEnabledRPC.set(3, postOptions.isGoogleWebToolkit());
            targetParamsEnabledRPC.set(5, postOptions.isDirectWebRemoting());
        }

        targetParamsInjectable.set(4, inputVectors.isUrlPath());

        InputVectors.HttpHeaders headersOptions = inputVectors.getHttpHeaders();
        if (headersOptions != null) {
            targetParamsInjectable.set(3, headersOptions.isEnabled());
            params.setScanHeadersAllRequests(headersOptions.isAllRequests());
        }

        InputVectors.CookieData cookieOptions = inputVectors.getCookieData();
        if (cookieOptions != null) {
            targetParamsInjectable.set(2, cookieOptions.isEnabled());
            params.setEncodeCookieValues(cookieOptions.isEncodeCookieValues());
        }

        targetParamsEnabledRPC.set(7, inputVectors.isScripts());

        params.setTargetParamsInjectable(toInt(targetParamsInjectable));
        params.setTargetParamsEnabledRPC(toInt(targetParamsEnabledRPC));
    }

    private static BitSet fromInt(int value) {
        return BitSet.valueOf(new long[] {value});
    }

    private static int toInt(BitSet bitSet) {
        long[] value = bitSet.toLongArray();
        if (value.length == 0) {
            return 0;
        }
        return (int) value[0];
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        try {
            Model.getSingleton().getSession().setExcludeFromScanRegexs(data.getExcludePaths());
        } catch (DatabaseException e) {
            progress.error(
                    Constant.messages.getString("automation.dialog.error.misc", e.getMessage()));
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public boolean isExcludeParam(String param) {
        switch (param) {
            case "allowAttackOnStart":
            case "attackPolicy":
            case "hostPerScan":
            case "maxChartTimeInMins":
            case "maxResultsToList":
            case "maxScansInUI":
            case "promptInAttackMode":
            case "promptToClearFinishedScans":
            case "rescanInAttackMode":
            case "showAdvancedDialog":
            case "targetParamsInjectable":
            case "targetParamsEnabledRPC":
                return true;
            default:
                return false;
        }
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString("automation.dialog.ascanconfig.summary");
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public Parameters getParameters() {
        return parameters;
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
        return ascan;
    }

    @Override
    public String getParamMethodName() {
        return OPTIONS_METHOD_NAME;
    }

    @Override
    public void showDialog() {
        new ActiveScanConfigJobDialog(this).setVisible(true);
    }

    @Getter
    public static class Data extends JobData {
        private final Parameters parameters;
        private final InputVectors inputVectors;
        @Setter private List<String> excludePaths = new ArrayList<>();

        public Data(AutomationJob job, Parameters parameters, InputVectors inputVectors) {
            super(job);
            this.parameters = parameters;
            this.inputVectors = inputVectors;
        }
    }

    @Getter
    @Setter
    public static class Parameters extends AutomationData {

        private Integer maxRuleDurationInMins = 0;
        private Integer maxScanDurationInMins = 0;
        private Integer maxAlertsPerRule = 0;
        private String defaultPolicy = "";
        private Boolean handleAntiCSRFTokens = true;
        private Boolean injectPluginIdInHeader = false;
        private Integer threadPerHost = Constants.getDefaultThreadCount();
    }

    @Getter
    @Setter
    public static class InputVectors {

        private UrlQueryStringAndDataDrivenNodes urlQueryStringAndDataDrivenNodes;
        private PostData postData;
        private boolean urlPath;
        private HttpHeaders httpHeaders;
        private CookieData cookieData;
        private boolean scripts = true;

        @Getter
        @Setter
        public static class UrlQueryStringAndDataDrivenNodes {

            private boolean enabled = true;
            private boolean addParam;
            private boolean odata = true;
        }

        @Getter
        @Setter
        public static class PostData {

            private boolean enabled = true;
            private boolean multiPartFormData = true;
            private boolean xml = true;
            private Json json;
            private boolean googleWebToolkit;
            private boolean directWebRemoting;

            @Getter
            @Setter
            public static class Json {
                private boolean enabled = true;
                private boolean scanNullValues;
            }
        }

        @Getter
        @Setter
        public static class HttpHeaders {

            private boolean enabled;
            private boolean allRequests;
        }

        @Getter
        @Setter
        public static class CookieData {
            private boolean enabled;
            private boolean encodeCookieValues;
        }
    }
}
