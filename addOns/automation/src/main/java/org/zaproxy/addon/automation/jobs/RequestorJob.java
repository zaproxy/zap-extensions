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

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.automation.AutomationData;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.gui.RequestorJobDialog;
import org.zaproxy.zap.utils.ThreadUtils;

public class RequestorJob extends AutomationJob {

    public static final String JOB_NAME = "requestor";
    private static final String REQUESTS = "requests";

    private Data data;

    private static final Logger LOG = LogManager.getLogger(RequestorJob.class);
    private HttpSender httpSender =
            new HttpSender(
                    Model.getSingleton().getOptionsParam().getConnectionParam(),
                    true,
                    HttpSender.MANUAL_REQUEST_INITIATOR);

    public RequestorJob() {
        this.data = new Data(this);
    }

    public RequestorJob(HttpSender httpSender) {
        this();
        this.httpSender = httpSender;
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        LinkedHashMap<?, ?> jobData = this.getJobData();
        Object o = jobData.get(REQUESTS);
        if (o == null) {
            return;
        }
        if (!(o instanceof ArrayList<?>)) {
            progress.error(Constant.messages.getString("automation.error.requestor.badlist", o));
            return;
        }
        ArrayList<?> requests = (ArrayList<?>) o;
        for (Object request : requests) {
            if (request instanceof LinkedHashMap<?, ?>) {
                Request req = new Request();
                JobUtils.applyParamsToObject(
                        (LinkedHashMap<?, ?>) request, req, this.getName(), null, progress);
                if (req.getUrl() == null) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.requestor.badurl",
                                    this.getName(),
                                    req.getUrl(),
                                    request));
                    continue;
                } else if (!req.getUrl().contains("${")) {
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

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {

        for (Request req : this.getData().getRequests()) {
            HttpMessage msg = new HttpMessage();
            String method = req.getMethod();
            if (method == null || method.isEmpty()) {
                method = "GET";
            }
            msg.getRequestHeader().setMethod(method);
            try {
                msg.getRequestHeader().setURI(new URI(req.getUrl(), true));
            } catch (URIException e) {
                // Handled above
            }
            String name = req.getName();
            if (name == null) {
                name =
                        msg.getRequestHeader().getMethod()
                                + msg.getRequestHeader().getURI().toString();
            }
            if (req.getData() != null) {
                msg.getRequestBody().setBody(req.getData());
                msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
            }
            try {
                httpSender.sendAndReceive(msg);
            } catch (IOException e) {
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
                                    msg,
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
            LOG.error(e.getMessage(), e);
            return;
        }

        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
                    });
        } catch (Exception e) {
            LOG.error("Could not add message to sites tree.", e);
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

    public static class Data extends JobData {
        private List<Request> requests = new ArrayList<>();

        public Data(AutomationJob job) {
            super(job);
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
    }

    public static class Request extends AutomationData {
        private String url;
        private String name;
        private String method;
        private String data;
        private Integer responseCode;

        public Request() {}

        public Request(String url, String name, String method, String data, Integer responseCode) {
            this.url = url;
            this.name = name;
            this.method = method;
            this.data = data;
            this.responseCode = responseCode;
        }

        public Request copy() {
            return new Request(url, name, method, data, responseCode);
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
    }
}
