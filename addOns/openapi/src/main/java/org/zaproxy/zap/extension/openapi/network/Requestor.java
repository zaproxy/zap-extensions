/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.network;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class Requestor {

    private final int initiator;
    private List<RequesterListener> listeners = new ArrayList<RequesterListener>();
    private HttpSender sender;
    private static final Logger LOG = Logger.getLogger(Requestor.class);

    public Requestor(int initiator) {
        this.initiator = initiator;
        sender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        initiator);
    }

    public List<String> run(List<RequestModel> requestsModel) {
        List<String> errors = new ArrayList<String>();
        try {
            for (RequestModel requestModel : requestsModel) {
                String url = requestModel.getUrl();
                HttpMessage httpRequest = new HttpMessage(new URI(url, false));
                httpRequest.getRequestHeader().setMethod(requestModel.getMethod().name());
                for (HttpHeaderField hhf : requestModel.getHeaders()) {
                    httpRequest.getRequestHeader().setHeader(hhf.getName(), hhf.getValue());
                }
                httpRequest.getRequestBody().setBody(requestModel.getBody());
                httpRequest
                        .getRequestHeader()
                        .setContentLength(httpRequest.getRequestBody().length());

                try {
                    sender.sendAndReceive(httpRequest, true);

                    for (RequesterListener listener : listeners) {
                        try {
                            listener.handleMessage(httpRequest, initiator);
                        } catch (Exception e) {
                            // Dont add handler errors to the list returned - these are assumed to
                            // be handler specific
                            LOG.error(e.getMessage(), e);
                        }
                    }
                } catch (IOException e) {
                    errors.add(
                            Constant.messages.getString(
                                    "openapi.import.error",
                                    url,
                                    e.getClass().getName(),
                                    e.getMessage()));
                    LOG.debug(e.getMessage(), e);
                }
            }
        } catch (IOException e) {
            errors.add(e.getMessage());
            LOG.error(e.getMessage(), e);
        }
        return errors;
    }

    public String getResponseBody(URI uri) throws NullPointerException, IOException {
        HttpMessage httpRequest = new HttpMessage(uri);
        httpRequest.getRequestHeader().setHeader("Accept", "application/json,*/*");
        sender.sendAndReceive(httpRequest, true);
        for (RequesterListener listener : listeners) {
            try {
                listener.handleMessage(httpRequest, initiator);
            } catch (Exception e) {
                LOG.error(e.getMessage(), e);
            }
        }
        return httpRequest.getResponseBody().toString();
    }

    public void addListener(RequesterListener listener) {
        this.listeners.add(listener);
    }

    public void removeListener(RequesterListener listener) {
        this.listeners.remove(listener);
    }
}
