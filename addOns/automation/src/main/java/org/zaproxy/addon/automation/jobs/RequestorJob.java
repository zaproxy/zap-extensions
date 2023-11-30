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

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.util.StdConverter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.RequestorJobDialog;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ThreadUtils;

public class RequestorJob extends AutomationJob {

    public static final String JOB_NAME = "requestor";
    private static final String REQUESTS = "requests";

    private static final Pattern HTTP_VERSION_PATTERN = Pattern.compile("HTTP/\\d+(?:\\.\\d+)?");

    private Parameters parameters = new Parameters();
    private Data data;

    private static final Logger LOGGER = LogManager.getLogger(RequestorJob.class);
    private HttpSender httpSender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

    public RequestorJob() {
        this.data = new Data(this, parameters);
    }

    public RequestorJob(HttpSender httpSender) {
        this();
        this.httpSender = httpSender;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) jobData.get("parameters");
        JobUtils.applyParamsToObject(params, this.parameters, this.getName(), null, progress);

        this.verifyUser(this.getParameters().getUser(), progress);

        Object requestsList = jobData.get(REQUESTS);
        if (requestsList == null) {
            return;
        }

        if (!(requestsList instanceof ArrayList<?>)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.requestor.badlist", requestsList));
            return;
        }

        ArrayList<?> requests = (ArrayList<?>) requestsList;
        for (Object request : requests) {
            if (request instanceof LinkedHashMap<?, ?>) {
                Request req = new Request();
                JobUtils.applyParamsToObject( // Here request needs to be mapped to req object
                        (LinkedHashMap<?, ?>) request, req, this.getName(), null, progress);
                if (validateHttpVersion(progress, request, req)) {
                    continue;
                }
                if (req.getUrl() == null) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.requestor.badurl",
                                    this.getName(),
                                    req.getUrl(),
                                    request));
                    continue;
                } else if (!JobUtils.containsVars(req.getUrl())) {
                    try {
                        new URI(req.getUrl(), true);
                    } catch (URIException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.requestor.badurl",
                                        this.getName(),
                                        req.getUrl(),
                                        request));
                    }
                }
                if (req.getResponseCode() != null
                        && (req.getResponseCode() < 100 || req.getResponseCode() > 599)) {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.requestor.badcode",
                                    this.getName(),
                                    req.getResponseCode(),
                                    request));
                }
                this.getData().addRequest(req);
            }
        }
    }

    public static boolean isValidHttpVersion(String httpVersion) {
        return httpVersion == null
                || httpVersion.isBlank()
                || HTTP_VERSION_PATTERN.matcher(httpVersion).matches();
    }

    private boolean validateHttpVersion(AutomationProgress progress, Object request, Request req) {
        String httpVersion = req.getHttpVersion();
        if (isValidHttpVersion(httpVersion)) {
            return false;
        }

        progress.error(
                Constant.messages.getString(
                        "automation.error.requestor.httpversion", getName(), httpVersion, request));
        return true;
    }

    @Override
    public void applyParameters(AutomationProgress progress) {}

    /**
     * This method sets the headers plus other required components of an HTTP message and then sends
     * the HTTP request.
     */
    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        for (Request req : this.getData().getRequests()) {
            HttpMessage msg = new HttpMessage();
            String method = req.getMethod();
            if (method == null || method.isEmpty()) {
                method = "GET";
            }
            List<Request.Header> headers = req.getHeaders();
            if (headers != null) {
                for (Request.Header header : headers) {
                    msg.getRequestHeader().addHeader(header.getName(), header.getValue());
                }
            }
            msg.getRequestHeader().setMethod(method);
            String httpVersion = req.getHttpVersion();
            if (httpVersion == null || httpVersion.isBlank()) {
                httpVersion = HttpHeader.HTTP11;
            }
            msg.getRequestHeader().setVersion(httpVersion);
            String url = env.replaceVars(req.getUrl());
            try {
                msg.getRequestHeader().setURI(new URI(url, true));
            } catch (URIException e) {
                // Will not have been reported above if the URL contains envvars
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.requestor.badurl", this.getName(), url, e));
                return;
            }
            String name = req.getName();
            if (name == null) {
                name =
                        msg.getRequestHeader().getMethod()
                                + msg.getRequestHeader().getURI().toString();
            }
            if (!StringUtils.isEmpty(req.getData())) {
                msg.getRequestBody().setBody(env.replaceVars(req.getData()));
                msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            }
            User user = this.getUser(this.getParameters().getUser(), progress);

            try {
                if (user != null) {
                    msg.setRequestingUser(user);
                    progress.info(
                            Constant.messages.getString(
                                    "automation.info.requrluser",
                                    this.getName(),
                                    msg.getRequestHeader().getURI(),
                                    user.getName()));
                } else {
                    progress.info(
                            Constant.messages.getString(
                                    "automation.info.requrl",
                                    this.getName(),
                                    msg.getRequestHeader().getURI()));
                }
                httpSender.sendAndReceive(msg);
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.requestor.badnetwork", this.getName(), name, e));
                return;
            }
            persistToHistoryAndSitesTree(msg);
            if (req.getResponseCode() != null) {
                int receivedCode = msg.getResponseHeader().getStatusCode();
                if (receivedCode != req.getResponseCode()) {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.requestor.codemismatch",
                                    msg.getRequestHeader().getMethod()
                                            + " "
                                            + msg.getRequestHeader().getURI(),
                                    req.getResponseCode(),
                                    receivedCode));
                }
            }
        }
    }

    @Override
    public String getExtraConfigFileData() {
        return "    requests:\n"
                + "      - url:                          # URL of the request to be made\n"
                + "        method:                       # A non-empty request method\n";
    }

    private void persistToHistoryAndSitesTree(HttpMessage msg) {
        HistoryReference historyRef;
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_ZAP_USER, msg);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return;
        }

        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
                    });
        } catch (Exception e) {
            LOGGER.error("Could not add message to sites tree.", e);
        }
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public Order getOrder() {
        return Order.FIRST_EXPLORE;
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
        new RequestorJobDialog(this).setVisible(true);
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "automation.dialog.requestor.summary", this.getData().getRequests().size());
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
        private List<Request> requests = new ArrayList<>();

        public Data(AutomationJob job, Parameters parameters) {
            super(job);
            this.parameters = parameters;
        }

        public List<Request> getRequests() {
            return requests.stream().map(r -> r.copy()).collect(Collectors.toList());
        }

        public void setRequests(List<Request> requests) {
            this.requests = requests;
        }

        public void addRequest(Request req) {
            this.requests.add(req);
        }

        public Parameters getParameters() {
            return parameters;
        }
    }

    public static class Parameters extends AutomationData {
        private String user;

        public Parameters() {}

        public String getUser() {
            return user;
        }

        public void setUser(String user) {
            this.user = user;
        }
    }

    public static class Request extends AutomationData {
        private String url;
        private String name;
        private String method;
        private String httpVersion;
        private List<Header> headers;
        private String data;
        private Integer responseCode;

        public Request() {}

        public Request(String url, String name, String method, String data, Integer responseCode) {
            this(url, name, method, data, responseCode, null);
        }

        public Request(
                String url,
                String name,
                String method,
                String data,
                Integer responseCode,
                List<Header> headers) {
            this(url, name, method, HttpHeader.HTTP11, data, responseCode, headers);
        }

        public Request(
                String url,
                String name,
                String method,
                String httpVersion,
                String data,
                Integer responseCode,
                List<Header> headers) {
            this.url = url;
            this.name = name;
            this.method = method;
            this.httpVersion = httpVersion;
            this.data = data;
            this.responseCode = responseCode;
            this.headers = headers;
        }

        public Request copy() {
            return new Request(url, name, method, httpVersion, data, responseCode, headers);
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }

        public String getHttpVersion() {
            return httpVersion;
        }

        public void setHttpVersion(String httpVersion) {
            this.httpVersion = httpVersion;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        public Integer getResponseCode() {
            return responseCode;
        }

        public void setResponseCode(Integer responseCode) {
            this.responseCode = responseCode;
        }

        public List<Header> getHeaders() {
            return headers;
        }

        private static List<Header> convertStringListToHeadersList(List<String> stringHeaders) {
            List<Header> headers = new ArrayList<>();
            if (stringHeaders != null) {

                for (String stringHeader : stringHeaders) {
                    String[] array = stringHeader.split(":", 2);
                    Header header = new Header();
                    header.setName(array[0]);
                    if (array.length > 1) {
                        header.setValue(array[1]);
                    }
                    headers.add(header);
                }
            }
            return headers;
        }

        public void setHeaders(List<String> headers) {
            this.headers = convertStringListToHeadersList(headers);
        }

        public void setHeadersList(List<Header> headers) {
            this.headers = headers;
        }

        @JsonSerialize(converter = HeaderConverter.class)
        public static class Header {
            private String name;
            private String value;

            public Header() {
                this.name = "";
                this.value = "";
            }

            public Header(String name, String value) {
                this.name = name;
                this.value = value;
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

        static class HeaderConverter extends StdConverter<Request.Header, String> {
            @Override
            public String convert(Request.Header header) {
                return header.getName() + ":" + header.getValue();
            }
        }
    }
}
