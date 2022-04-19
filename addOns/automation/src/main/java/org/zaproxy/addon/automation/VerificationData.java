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
package org.zaproxy.addon.automation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthPollFrequencyUnits;
import org.zaproxy.zap.model.Context;

public class VerificationData extends AutomationData {

    public static final String METHOD_BOTH = "both";
    public static final String METHOD_RESPONSE = "response";
    public static final String METHOD_REQUEST = "request";
    public static final String METHOD_POLL = "poll";

    public static final String POLL_UNIT_REQUESTS = "requests";
    public static final String POLL_UNIT_SECONDS = "seconds";

    private static List<String> validMethods =
            Arrays.asList(METHOD_BOTH, METHOD_RESPONSE, METHOD_REQUEST, METHOD_POLL);

    private static List<String> validPollUnits =
            Arrays.asList(POLL_UNIT_REQUESTS, POLL_UNIT_SECONDS);

    public static final String POLL_HEADERS_ELEMENT = "pollAdditionalHeaders";

    private String method;
    private String loggedInRegex;
    private String loggedOutRegex;
    private Integer pollFrequency;
    private String pollUnits;
    private String pollUrl;
    private String pollPostData;
    private List<AdditionalHeaderData> pollAdditionalHeaders;

    public VerificationData() {}

    public VerificationData(Context context) {
        AuthenticationMethod authMethod = context.getAuthenticationMethod();
        switch (authMethod.getAuthCheckingStrategy()) {
            case EACH_REQ:
                this.setMethod(METHOD_REQUEST);
                break;
            case EACH_REQ_RESP:
                this.setMethod(METHOD_BOTH);
                break;
            case EACH_RESP:
                this.setMethod(METHOD_RESPONSE);
                break;
            case POLL_URL:
            default:
                this.setMethod(METHOD_POLL);
                break;
        }
        if (authMethod.getLoggedInIndicatorPattern() != null) {
            this.setLoggedInRegex(authMethod.getLoggedInIndicatorPattern().pattern());
        }
        if (authMethod.getLoggedOutIndicatorPattern() != null) {
            this.setLoggedOutRegex(authMethod.getLoggedOutIndicatorPattern().pattern());
        }
        this.setPollFrequency(authMethod.getPollFrequency());

        if (AuthPollFrequencyUnits.REQUESTS.equals(authMethod.getPollFrequencyUnits())) {
            this.setPollUnits(POLL_UNIT_REQUESTS);
        } else {
            this.setPollUnits(POLL_UNIT_SECONDS);
        }
        this.setPollUrl(authMethod.getPollUrl());
        this.setPollPostData(authMethod.getPollData());
        String headers = authMethod.getPollHeaders();
        if (headers != null) {
            List<AdditionalHeaderData> headerList = new ArrayList<>();
            for (String header : headers.split("\n")) {
                String[] headerValue = header.split(":");
                if (headerValue.length == 2) {
                    headerList.add(
                            new AdditionalHeaderData(headerValue[0].trim(), headerValue[1].trim()));
                }
            }
            if (!headerList.isEmpty()) {
                this.setPollAdditionalHeaders(headerList);
            }
        }
    }

    public VerificationData(Object data, AutomationProgress progress) {
        if (!(data instanceof LinkedHashMap)) {
            progress.error(
                    Constant.messages.getString("automation.error.env.badverification", data));
        } else {
            LinkedHashMap<?, ?> dataMap = (LinkedHashMap<?, ?>) data;
            JobUtils.applyParamsToObject(
                    dataMap, this, "verification", new String[] {POLL_HEADERS_ELEMENT}, progress);

            if (!StringUtils.isEmpty(method)
                    && !validMethods.contains(method.toLowerCase(Locale.ROOT))) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.env.verification.type.bad", data));
            }
            if (!StringUtils.isEmpty(pollUnits)
                    && !validPollUnits.contains(pollUnits.toLowerCase(Locale.ROOT))) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.env.verification.pollunits.bad", data));
            }

            if (!StringUtils.isEmpty(this.loggedInRegex)) {
                try {
                    Pattern.compile(this.loggedInRegex);
                } catch (Exception e) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.verification.loginregex.bad",
                                    this.getLoggedInRegex()));
                }
            }

            if (!StringUtils.isEmpty(this.loggedOutRegex)) {
                try {
                    Pattern.compile(this.loggedOutRegex);
                } catch (Exception e) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.verification.logoutregex.bad",
                                    this.getLoggedOutRegex()));
                }
            }

            if (dataMap.containsKey(POLL_HEADERS_ELEMENT)) {
                Object headersObj = dataMap.get(POLL_HEADERS_ELEMENT);
                if (headersObj instanceof List) {
                    List<?> headersList = (List<?>) headersObj;
                    List<AdditionalHeaderData> ahdList = new ArrayList<>();
                    for (Object header : headersList) {
                        if (!(header instanceof LinkedHashMap)) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.verification.header.bad",
                                            header));
                        } else {
                            LinkedHashMap<?, ?> headerMap = (LinkedHashMap<?, ?>) header;
                            AdditionalHeaderData ahd = new AdditionalHeaderData();
                            JobUtils.applyParamsToObject(
                                    headerMap, ahd, POLL_HEADERS_ELEMENT, null, progress);
                            ahdList.add(ahd);
                        }
                    }
                    if (!ahdList.isEmpty()) {
                        this.setPollAdditionalHeaders(ahdList);
                    }
                }
            }
        }
    }

    public void initAuthenticationVerification(Context context, AutomationProgress progress) {
        AuthenticationMethod authMethod = context.getAuthenticationMethod();
        switch (this.getMethod().toLowerCase(Locale.ROOT)) {
            case METHOD_BOTH:
                authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.EACH_REQ_RESP);
                break;
            case METHOD_RESPONSE:
                authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.EACH_RESP);
                break;
            case METHOD_REQUEST:
                authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.EACH_REQ);
                break;
            case METHOD_POLL:
            default:
                authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.POLL_URL);
                break;
        }
        if (POLL_UNIT_REQUESTS.equalsIgnoreCase(this.getPollUnits())) {
            authMethod.setPollFrequencyUnits(AuthPollFrequencyUnits.REQUESTS);
        } else {
            authMethod.setPollFrequencyUnits(AuthPollFrequencyUnits.SECONDS);
        }
        try {
            authMethod.setLoggedInIndicatorPattern(this.getLoggedInRegex());
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.env.verification.loginregex.bad",
                            this.getLoggedInRegex()));
        }
        try {
            authMethod.setLoggedOutIndicatorPattern(this.getLoggedOutRegex());
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.env.verification.logoutregex.bad",
                            this.getLoggedOutRegex()));
        }
        authMethod.setPollUrl(this.getPollUrl());
        authMethod.setPollFrequency(JobUtils.unBox(this.getPollFrequency()));
        authMethod.setPollData(this.getPollPostData());
        if (this.pollAdditionalHeaders != null && !this.pollAdditionalHeaders.isEmpty()) {
            StringBuilder headers = new StringBuilder();
            for (AdditionalHeaderData header : this.pollAdditionalHeaders) {
                headers.append(header.getHeader());
                headers.append(':');
                headers.append(header.getValue());
                headers.append('\n');
            }
            authMethod.setPollHeaders(headers.toString());
        }
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getLoggedInRegex() {
        return loggedInRegex;
    }

    public void setLoggedInRegex(String loggedInRegex) {
        this.loggedInRegex = loggedInRegex;
    }

    public String getLoggedOutRegex() {
        return loggedOutRegex;
    }

    public void setLoggedOutRegex(String loggedOutRegex) {
        this.loggedOutRegex = loggedOutRegex;
    }

    public Integer getPollFrequency() {
        return pollFrequency;
    }

    public void setPollFrequency(Integer pollFrequency) {
        this.pollFrequency = pollFrequency;
    }

    public String getPollUnits() {
        return pollUnits;
    }

    public void setPollUnits(String pollUnits) {
        this.pollUnits = pollUnits;
    }

    public String getPollUrl() {
        return pollUrl;
    }

    public void setPollUrl(String pollUrl) {
        this.pollUrl = pollUrl;
    }

    public String getPollPostData() {
        return pollPostData;
    }

    public void setPollPostData(String pollPostData) {
        this.pollPostData = pollPostData;
    }

    public List<AdditionalHeaderData> getPollAdditionalHeaders() {
        return pollAdditionalHeaders;
    }

    public void setPollAdditionalHeaders(List<AdditionalHeaderData> pollAdditionalHeaders) {
        this.pollAdditionalHeaders = pollAdditionalHeaders;
    }

    public static class AdditionalHeaderData extends AutomationData {
        private String header;
        private String value;

        public AdditionalHeaderData() {}

        public AdditionalHeaderData(String header, String value) {
            this.header = header;
            this.value = value;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
