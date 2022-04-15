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
package org.zaproxy.addon.automation.tests;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.UrlPresenceTestDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;

public class UrlPresenceTest extends AbstractAutomationTest {

    public static final String TEST_TYPE = "url";

    private static final String PARAM_NAME = "name";
    private static final String PARAM_ON_FAIL = "onFail";
    private static final String PARAM_URL = "url";
    private static final String PARAM_OPERATOR = "operator";
    private static final String PARAM_REQUEST_HEADER_REGEX = "requestHeaderRegex";
    private static final String PARAM_REQUEST_BODY_REGEX = "requestBodyRegex";
    private static final String PARAM_RESPONSE_HEADER_REGEX = "responseHeaderRegex";
    private static final String PARAM_RESPONSE_BODY_REGEX = "responseBodyRegex";

    private Data data;

    public enum Operator {
        OR,
        AND;

        public String getI18nString() {
            return Constant.messages.getString(
                    "automation.dialog.urlpresencetest.operator."
                            + this.name().toLowerCase(Locale.ROOT));
        }
    }

    public UrlPresenceTest(Map<?, ?> testData, AutomationJob job, AutomationProgress progress) {
        super(testData, job);
        data = new Data(this);
        JobUtils.applyParamsToObject(testData, this.getData(), this.getName(), null, progress);

        if (this.getData().getOnFail() == null) {
            progress.error(
                    Constant.messages.getString(
                            "automation.test.error.badonfail", getJobType(), this.getName()));
        }

        String operator = this.getData().getOperator();
        if (StringUtils.isEmpty(operator)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.test.url.error.badoperator", getJobType(), this.getName()));
        }
        if (StringUtils.isEmpty(this.getData().getUrl())) {
            progress.error(
                    Constant.messages.getString(
                            "automation.test.url.error.badurl", getJobType(), this.getName()));
        }
        if (!StringUtils.isEmpty(this.getData().getRequestHeaderRegex())) {
            compilePattern(this.getData().getRequestHeaderRegex(), progress);
        }
        if (!StringUtils.isEmpty(this.getData().getRequestBodyRegex())) {
            compilePattern(this.getData().getRequestBodyRegex(), progress);
        }
        if (!StringUtils.isEmpty(this.getData().getResponseHeaderRegex())) {
            compilePattern(this.getData().getResponseHeaderRegex(), progress);
        }
        if (!StringUtils.isEmpty(this.getData().getResponseBodyRegex())) {
            compilePattern(this.getData().getResponseBodyRegex(), progress);
        }
    }

    public static LinkedHashMap<?, ?> paramsToData(
            String name,
            String onFail,
            String operator,
            String url,
            String requestHeaderRegex,
            String requestBodyRegex,
            String responseHeaderRegex,
            String responseBodyRegex) {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put(PARAM_NAME, name);
        map.put(PARAM_ON_FAIL, onFail);
        map.put(PARAM_OPERATOR, operator);
        map.put(PARAM_URL, url);
        map.put(PARAM_REQUEST_HEADER_REGEX, requestHeaderRegex);
        map.put(PARAM_REQUEST_BODY_REGEX, requestBodyRegex);
        map.put(PARAM_RESPONSE_HEADER_REGEX, responseHeaderRegex);
        map.put(PARAM_RESPONSE_BODY_REGEX, responseBodyRegex);
        return map;
    }

    public UrlPresenceTest(
            String name,
            String onFail,
            String operator,
            String url,
            String requestHeaderRegex,
            String requestBodyRegex,
            String responseHeaderRegex,
            String responseBodyRegex,
            AutomationJob job,
            AutomationProgress progress) {
        this(
                paramsToData(
                        name,
                        onFail,
                        operator,
                        url,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex),
                job,
                progress);
    }

    public UrlPresenceTest(AutomationJob job, AutomationProgress progress)
            throws IllegalArgumentException {
        super("", AbstractAutomationTest.OnFail.INFO.name(), job);
        data = new Data(this);
        data.setOnFail(AbstractAutomationTest.OnFail.INFO);
    }

    @Override
    public String getTestType() {
        return TEST_TYPE;
    }

    private Pattern compilePattern(String regex, AutomationProgress progress) {
        try {
            return Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            progress.warn(
                    Constant.messages.getString(
                            "automation.tests.url.badregex",
                            getJobType(),
                            regex,
                            getName(),
                            e.getMessage()));
        }
        return null;
    }

    private boolean checkPattern(
            String regex, String msg, AutomationProgress progress, String operator) {
        if (regex == null) {
            return false;
        }
        if (StringUtils.isEmpty(regex)
                && (operator.equalsIgnoreCase("or") || StringUtils.isEmpty(operator))) {
            return false;
        }
        Pattern pattern = compilePattern(regex, progress);
        boolean match = false;
        if (pattern != null) {
            match = pattern.matcher(msg).find();
        }
        return match;
    }

    @Override
    public boolean runTest(AutomationProgress progress) {
        OnFail onFail = this.getData().getOnFail();
        URI uri = null;
        AutomationEnvironment env = this.getJob().getEnv();
        try {
            String uriString = env.replaceVars(this.getData().getUrl());
            try {
                uri = new URI(uriString, true);
            } catch (Exception e) {
                String baduri =
                        Constant.messages.getString(
                                "automation.tests.url.error.badurl",
                                getJobType(),
                                this.getName(),
                                this.getData().getUrl(),
                                e.getMessage());
                setOnFailMessage(baduri, progress, onFail);
                return false;
            }
            SiteMap tree = Model.getSingleton().getSession().getSiteTree();
            if (tree == null) {
                String noTree =
                        Constant.messages.getString(
                                "automation.tests.url.siteTreeNotFound",
                                getJobType(),
                                this.getName(),
                                this.getTestType());
                setOnFailMessage(noTree, progress, onFail);
                return false;
            }
            SiteNode node = tree.findNode(uri);
            if (node == null) {
                String nodeMsg =
                        Constant.messages.getString(
                                "automation.tests.url.error.noMessage",
                                getJobType(),
                                this.getName(),
                                this.getTestType());
                setOnFailMessage(nodeMsg, progress, onFail);
                return false;
            }
            HttpMessage msg = node.getHistoryReference().getHttpMessage();
            String requestHeaderRegex = this.getData().getRequestHeaderRegex();
            String requestBodyRegex = this.getData().getRequestBodyRegex();
            String responseHeaderRegex = this.getData().getResponseHeaderRegex();
            String responseBodyRegex = this.getData().getResponseBodyRegex();
            String operator = this.getData().getOperator();
            boolean requestHeaderFound = false;
            boolean requestBodyFound = false;
            boolean responseHeaderFound = false;
            boolean responseBodyFound = false;
            boolean result = false;

            if (StringUtils.isEmpty(requestBodyRegex)
                    && StringUtils.isEmpty(requestHeaderRegex)
                    && StringUtils.isEmpty(responseBodyRegex)
                    && StringUtils.isEmpty(responseHeaderRegex)) {
                return true;
            }

            requestHeaderFound =
                    checkPattern(
                            requestHeaderRegex,
                            msg.getRequestHeader().toString(),
                            progress,
                            operator);
            requestBodyFound =
                    checkPattern(
                            requestBodyRegex, msg.getRequestBody().toString(), progress, operator);
            responseHeaderFound =
                    checkPattern(
                            responseHeaderRegex,
                            msg.getResponseHeader().toString(),
                            progress,
                            operator);
            responseBodyFound =
                    checkPattern(
                            responseBodyRegex,
                            msg.getResponseBody().toString(),
                            progress,
                            operator);

            if (operator.equalsIgnoreCase("and")) {
                result =
                        requestHeaderFound
                                && requestBodyFound
                                && responseHeaderFound
                                && responseBodyFound;
            } else if (operator.equalsIgnoreCase("or") || StringUtils.isEmpty(operator)) {
                result =
                        requestHeaderFound
                                || requestBodyFound
                                || responseHeaderFound
                                || responseBodyFound;
            } else {
                String badOperatorMessage =
                        Constant.messages.getString(
                                "automation.tests.url.badOperator",
                                getJobType(),
                                getName(),
                                getTestType(),
                                operator);
                setOnFailMessage(badOperatorMessage, progress, onFail);
            }
            return result;
        } catch (Exception e) {
            String message =
                    Constant.messages.getString(
                            "automation.tests.url.error",
                            getJobType(),
                            getName(),
                            getTestType(),
                            e.getMessage());
            setOnFailMessage(message, progress, onFail);
            return false;
        }
    }

    @Override
    public String getTestPassedMessage() {
        return Constant.messages.getString(
                "automation.tests.url.pass", getJobType(), getTestType(), this.getData().getName());
    }

    @Override
    public String getTestFailedMessage() {
        return Constant.messages.getString(
                "automation.tests.url.fail", getJobType(), getTestType(), this.getData().getName());
    }

    private static void setOnFailMessage(
            String onFailMessage, AutomationProgress progress, OnFail onFail) {
        switch (onFail) {
            case INFO:
                progress.info(onFailMessage);
                break;
            case WARN:
                progress.warn(onFailMessage);
                break;
            case ERROR:
                progress.error(onFailMessage);
                break;
            default:
                throw new RuntimeException("Unknown OnFail: " + onFail);
        }
    }

    @Override
    public Data getData() {
        return data;
    }

    @Override
    public void showDialog() {
        new UrlPresenceTestDialog(this).setVisible(true);
    }

    public static class Data extends TestData {
        private String url;
        private String requestHeaderRegex;
        private String requestBodyRegex;
        private String responseHeaderRegex;
        private String responseBodyRegex;
        private String operator;

        public Data(UrlPresenceTest test) {
            super(test);
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getRequestHeaderRegex() {
            return requestHeaderRegex;
        }

        public void setRequestHeaderRegex(String requestHeaderRegex) {
            this.requestHeaderRegex = requestHeaderRegex;
        }

        public String getRequestBodyRegex() {
            return requestBodyRegex;
        }

        public void setRequestBodyRegex(String requestBodyRegex) {
            this.requestBodyRegex = requestBodyRegex;
        }

        public String getResponseHeaderRegex() {
            return responseHeaderRegex;
        }

        public void setResponseHeaderRegex(String responseHeaderRegex) {
            this.responseHeaderRegex = responseHeaderRegex;
        }

        public String getResponseBodyRegex() {
            return responseBodyRegex;
        }

        public void setResponseBodyRegex(String responseBodyRegex) {
            this.responseBodyRegex = responseBodyRegex;
        }

        public String getOperator() {
            return operator;
        }

        public void setOperator(String operator) {
            this.operator = operator;
        }
    }
}
