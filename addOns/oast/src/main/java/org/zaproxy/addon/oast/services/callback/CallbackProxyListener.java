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
package org.zaproxy.addon.oast.services.callback;

import java.util.Date;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.oast.OastRequest;
import org.zaproxy.zap.utils.ThreadUtils;

class CallbackProxyListener implements OverrideMessageProxyListener {

    private static final Logger LOGGER = LogManager.getLogger(CallbackProxyListener.class);

    private final CallbackService callbackService;

    public CallbackProxyListener(CallbackService callbackService) {
        this.callbackService = callbackService;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    @Override
    public boolean onHttpResponseReceived(HttpMessage msg) {
        return true;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        try {
            msg.setTimeSentMillis(new Date().getTime());
            String url = msg.getRequestHeader().getURI().toString();
            String path = msg.getRequestHeader().getURI().getPath();
            LOGGER.debug(
                    "Callback received for URL : {} path : {} from {}",
                    url,
                    path,
                    msg.getRequestHeader().getSenderAddress());

            msg.setResponseHeader(HttpHeader.HTTP11 + " " + HttpStatusCode.OK);

            if (path.startsWith("/" + CallbackService.TEST_PREFIX)) {
                String str =
                        Constant.messages.getString(
                                "oast.callback.test.msg",
                                url,
                                msg.getRequestHeader().getSenderAddress().toString());
                if (View.isInitialised()) {
                    View.getSingleton().getOutputPanel().appendAsync(str + "\n");
                }
                LOGGER.info(str);
                callbackReceived(
                        Constant.messages.getString("oast.callback.handler.test.name"), msg);
                return true;
            } else if (path.startsWith("/favicon.ico")) {
                // Just ignore - it's automatically requested by browsers
                // e.g. when trying the test URL
                return true;
            }

            for (Map.Entry<String, CallbackImplementor> callback :
                    callbackService.getCallbacks().entrySet()) {
                if (path.startsWith(callback.getKey())) {
                    // Copy the message so that CallbackImplementors can't
                    // return anything to the sender
                    CallbackImplementor implementor = callback.getValue();
                    implementor.handleCallBack(msg.cloneAll());
                    callbackReceived(implementor.getClass().getSimpleName(), msg);
                    return true;
                }
            }

            callbackReceived(Constant.messages.getString("oast.callback.handler.none.name"), msg);
            LOGGER.error(
                    "No callback handler for URL : {} from {}",
                    url,
                    msg.getRequestHeader().getSenderAddress());
        } catch (URIException | HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return true;
    }

    private void callbackReceived(String handler, HttpMessage httpMessage) {
        ThreadUtils.invokeAndWaitHandled(() -> callbackReceivedHandler(handler, httpMessage));
    }

    private void callbackReceivedHandler(String handler, HttpMessage httpMessage) {
        try {
            OastRequest request =
                    OastRequest.create(
                            httpMessage,
                            httpMessage.getRequestHeader().getSenderAddress().getHostAddress(),
                            handler);
            callbackService.handleOastRequest(request);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist received callback:", e);
        }
    }
}
