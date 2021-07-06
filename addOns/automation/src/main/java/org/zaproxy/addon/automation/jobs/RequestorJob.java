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
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.utils.ThreadUtils;

public class RequestorJob extends AutomationJob {

    public static final String JOB_NAME = "requestor";
    private static final String REQUESTS = "requests";
    private static final String URL = "url";
    private static final String METHOD = "method";
    private static final String RESPONSECODE = "responseCode";
    private static final String NAME = "name";
    private static final String DATA = "data";

    private static final Logger LOG = LogManager.getLogger(RequestorJob.class);
    private HttpSender httpSender =
            new HttpSender(
                    Model.getSingleton().getOptionsParam().getConnectionParam(),
                    true,
                    HttpSender.MANUAL_REQUEST_INITIATOR);

    public RequestorJob() {}

    public RequestorJob(HttpSender httpSender) {
        this.httpSender = httpSender;
    }

    @Override
    public void verifyJobSpecificData(AutomationProgress progress) {
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
                LinkedHashMap<?, ?> requestMap = (LinkedHashMap<?, ?>) request;
                Object url = requestMap.get(URL);
                if (url instanceof String) {
                    String mUrl = (String) url;
                    try {
                        new URI(mUrl, true);
                    } catch (URIException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.requestor.badurl",
                                        this.getName(),
                                        mUrl,
                                        request));
                    }
                } else {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.requestor.badurl",
                                    this.getName(),
                                    url,
                                    request));
                }
                Object method = requestMap.get(METHOD);
                if (method != null && !(method instanceof String)) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.requestor.invalidmethod",
                                    this.getName(),
                                    method,
                                    request));
                }
                Object responseCode = requestMap.get(RESPONSECODE);
                if (responseCode instanceof String) {
                    String mResponseCode = (String) responseCode;
                    try {
                        int code = Integer.parseInt(mResponseCode);
                        if (code < 100 || code > 599) {
                            progress.warn(
                                    Constant.messages.getString(
                                            "automation.error.requestor.badcode",
                                            this.getName(),
                                            mResponseCode,
                                            request));
                        }
                    } catch (NumberFormatException e) {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.requestor.badcode",
                                        this.getName(),
                                        mResponseCode,
                                        request));
                    }
                } else if (responseCode != null) {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.requestor.badcode",
                                    this.getName(),
                                    responseCode,
                                    request));
                }
            }
        }
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        LinkedHashMap<?, ?> jobData = this.getJobData();
        ArrayList<?> requests = (ArrayList<?>) jobData.get(REQUESTS);
        if (requests != null) {
            for (Object request : requests) {
                LinkedHashMap<?, ?> requestMap = (LinkedHashMap<?, ?>) request;
                HttpMessage msg = new HttpMessage();
                String method = (String) requestMap.get(METHOD);
                if (method == null || method.isEmpty()) {
                    method = "GET";
                }
                msg.getRequestHeader().setMethod(method);
                try {
                    msg.getRequestHeader().setURI(new URI((String) requestMap.get(URL), true));
                } catch (URIException e) {
                    // Handled above
                }
                String name;
                if (requestMap.get(NAME) != null) {
                    name = (String) requestMap.get(NAME);
                } else {
                    name =
                            msg.getRequestHeader().getMethod()
                                    + msg.getRequestHeader().getURI().toString();
                }
                if (requestMap.get(DATA) != null) {
                    msg.getRequestBody().setBody((String) requestMap.get(DATA));
                    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
                }
                try {
                    httpSender.sendAndReceive(msg);
                } catch (IOException e) {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.requestor.badnetwork",
                                    this.getName(),
                                    name,
                                    e));
                    return;
                }
                persistToHistoryAndSitesTree(msg);
                Object o = requestMap.get(RESPONSECODE);
                if (o instanceof Integer) {
                    int expectedCode = (Integer) o;
                    int receivedCode = msg.getResponseHeader().getStatusCode();
                    if (receivedCode != expectedCode) {
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.requestor.codemismatch",
                                        msg,
                                        expectedCode,
                                        receivedCode));
                    }
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
}
