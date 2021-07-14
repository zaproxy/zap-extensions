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
package org.zaproxy.addon.oast.callback;

import java.awt.EventQueue;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.core.proxy.ProxyServer;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.OptionsChangedListener;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.base.OastOptionsPanelCard;
import org.zaproxy.addon.oast.base.OastServer;
import org.zaproxy.addon.oast.ui.OastRequest;

public class CallbackServer extends OastServer
        implements OptionsChangedListener, SessionChangedListener {

    private static final String TEST_PREFIX = "ZapTest";

    private final ProxyServer proxyServer;
    private org.zaproxy.addon.oast.callback.CallbackParam callbackParam;
    private CallbackOptionsPanelCard callbackOptionsPanelCard;

    private final Map<String, org.zaproxy.addon.oast.callback.CallbackImplementor> callbacks =
            new HashMap<>();
    private int actualPort;
    private String currentConfigLocalAddress;
    private int currentConfigPort;

    private static final Logger LOGGER = LogManager.getLogger(CallbackServer.class);

    private final ExtensionOast extensionOast;

    public CallbackServer(ExtensionOast extensionOast) {
        this.extensionOast = extensionOast;
        proxyServer = new ProxyServer("ZAP-CallbackServer");
        proxyServer.addOverrideMessageProxyListener(new CallbackProxyListener());
    }

    @Override
    public String getName() {
        return Constant.messages.getString("oast.callback.name");
    }

    @Override
    public OastOptionsPanelCard getOptionsPanelCard() {
        if (callbackOptionsPanelCard == null) {
            callbackOptionsPanelCard = new CallbackOptionsPanelCard(this);
        }
        return callbackOptionsPanelCard;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        LOGGER.debug("Adding Callback Params");
        extensionHook.addOptionsParamSet(getCallbackParam());
        LOGGER.debug("Added Callback Params");
        extensionHook.addOptionsChangedListener(this);
        extensionHook.addSessionListener(this);
    }

    @Override
    public void optionsLoaded() {
        proxyServer.setConnectionParam(
                extensionOast.getModel().getOptionsParam().getConnectionParam());
        currentConfigLocalAddress = this.getCallbackParam().getLocalAddress();
        currentConfigPort = this.getCallbackParam().getPort();
    }

    @Override
    public void postInit() {
        this.restartServer(this.getCallbackParam().getPort());
    }

    private void restartServer(int port) {
        // this will close the previous listener (if there was one)
        actualPort = proxyServer.startServer(this.getCallbackParam().getLocalAddress(), port, true);
        LOGGER.info(
                "Started callback server on "
                        + this.getCallbackParam().getLocalAddress()
                        + ":"
                        + actualPort);
    }

    public String getCallbackAddress() {
        String addr = this.getCallbackParam().getRemoteAddress();
        boolean ipv6 = addr.contains(":");
        String hostname = ipv6 ? "[" + addr + "]" : addr;

        boolean isSecure = this.getCallbackParam().isSecure();
        String scheme = isSecure ? "https" : "http";

        return scheme + "://" + hostname + ":" + actualPort + "/";
    }

    public String getTestUrl() {
        return getCallbackAddress() + TEST_PREFIX;
    }

    protected int getPort() {
        return actualPort;
    }

    public void registerCallbackImplementor(
            org.zaproxy.addon.oast.callback.CallbackImplementor impl) {
        for (String prefix : impl.getCallbackPrefixes()) {
            LOGGER.debug("Registering callback prefix: " + prefix);
            if (this.callbacks.containsKey(prefix)) {
                LOGGER.error("Duplicate callback prefix: " + prefix);
            }
            this.callbacks.put("/" + prefix, impl);
        }
    }

    public void removeCallbackImplementor(
            org.zaproxy.addon.oast.callback.CallbackImplementor impl) {
        for (String shortcut : impl.getCallbackPrefixes()) {
            String key = "/" + shortcut;
            if (this.callbacks.containsKey(key)) {
                LOGGER.debug("Removing registered callback prefix: " + shortcut);
                this.callbacks.remove(key);
            }
        }
    }

    private org.zaproxy.addon.oast.callback.CallbackParam getCallbackParam() {
        if (this.callbackParam == null) {
            this.callbackParam = new CallbackParam();
        }
        return this.callbackParam;
    }

    @Override
    public void optionsChanged(OptionsParam optionsParam) {
        if (!currentConfigLocalAddress.equals(this.getCallbackParam().getLocalAddress())
                || currentConfigPort != this.getCallbackParam().getPort()) {
            // Somethings changed, reuse the port if its still a random one
            int port = actualPort;
            if (currentConfigPort != this.getCallbackParam().getPort()) {
                port = this.getCallbackParam().getPort();
            }
            this.restartServer(port);

            // Save the new ones for next time
            currentConfigLocalAddress = this.getCallbackParam().getLocalAddress();
            currentConfigPort = this.getCallbackParam().getPort();
        }
    }

    @Override
    public void sessionChanged(Session session) {
        invokeIfRequiredAndViewIsInitialised(() -> sessionChangedEventHandler(session));
    }

    private void sessionChangedEventHandler(Session session) {
        extensionOast.getOastPanel().clearCallbackRequests();
        addCallbacksFromDatabaseIntoCallbackPanel(session);
    }

    private void addCallbacksFromDatabaseIntoCallbackPanel(Session session) {
        if (session == null) {
            return;
        }

        try {
            List<Integer> historyIds =
                    extensionOast
                            .getModel()
                            .getDb()
                            .getTableHistory()
                            .getHistoryIdsOfHistType(
                                    session.getSessionId(), HistoryReference.TYPE_OAST);

            for (int historyId : historyIds) {
                HistoryReference historyReference = new HistoryReference(historyId);
                OastRequest request = OastRequest.create(historyReference);
                extensionOast.getOastPanel().addCallbackRequest(request);
            }
        } catch (DatabaseException | HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public void deleteCallbacks() {
        deleteCallbacksFromDatabase();
        invokeIfRequiredAndViewIsInitialised(
                () -> extensionOast.getOastPanel().clearCallbackRequests());
    }

    private void deleteCallbacksFromDatabase() {
        try {
            extensionOast
                    .getModel()
                    .getDb()
                    .getTableHistory()
                    .deleteHistoryType(
                            extensionOast.getModel().getSession().getSessionId(),
                            HistoryReference.TYPE_OAST);
        } catch (DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void invokeIfRequiredAndViewIsInitialised(Runnable runnable) {
        if (hasView()) {
            if (!EventQueue.isDispatchThread()) {
                try {
                    EventQueue.invokeAndWait(runnable);
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
                return;
            }
            runnable.run();
        }
    }

    @Override
    public void sessionAboutToChange(Session session) {}

    @Override
    public void sessionScopeChanged(Session session) {}

    @Override
    public void sessionModeChanged(Control.Mode mode) {}

    private class CallbackProxyListener implements OverrideMessageProxyListener {

        @Override
        public int getArrangeableListenerOrder() {
            return 0;
        }

        @Override
        public boolean onHttpRequestSend(HttpMessage msg) {
            try {
                msg.setTimeSentMillis(new Date().getTime());
                String url = msg.getRequestHeader().getURI().toString();
                String path = msg.getRequestHeader().getURI().getPath();
                LOGGER.debug(
                        "Callback received for URL : "
                                + url
                                + " path : "
                                + path
                                + " from "
                                + msg.getRequestHeader().getSenderAddress());

                msg.setResponseHeader(HttpHeader.HTTP11 + " " + HttpStatusCode.OK);

                if (path.startsWith("/" + TEST_PREFIX)) {
                    String str =
                            Constant.messages.getString(
                                    "oast.callback.test.msg",
                                    url,
                                    msg.getRequestHeader().getSenderAddress().toString());
                    if (hasView()) {
                        extensionOast.getView().getOutputPanel().appendAsync(str + "\n");
                    }
                    LOGGER.info(str);
                    callbackReceived(
                            Constant.messages.getString("oast.callback.handler.test.name"), msg);
                    return true;
                } else if (path.startsWith("/favicon.ico")) {
                    // Just ignore - its automatically requested by browsers
                    // e.g. when trying the test URL
                    return true;
                }

                for (Entry<String, org.zaproxy.addon.oast.callback.CallbackImplementor> callback :
                        callbacks.entrySet()) {
                    if (path.startsWith(callback.getKey())) {
                        // Copy the message so that CallbackImplementors cant
                        // return anything to the sender
                        CallbackImplementor implementor = callback.getValue();
                        implementor.handleCallBack(msg.cloneAll());
                        callbackReceived(implementor.getClass().getSimpleName(), msg);
                        return true;
                    }
                }

                callbackReceived(
                        Constant.messages.getString("oast.callback.handler.none.name"), msg);
                LOGGER.error(
                        "No callback handler for URL : "
                                + url
                                + " from "
                                + msg.getRequestHeader().getSenderAddress());
            } catch (URIException | HttpMalformedHeaderException e) {
                LOGGER.error(e.getMessage(), e);
            }
            return true;
        }

        @Override
        public boolean onHttpResponseReceived(HttpMessage msg) {
            return true;
        }
    }

    private void callbackReceived(String handler, HttpMessage httpMessage) {
        invokeIfRequiredAndViewIsInitialised(() -> callbackReceivedHandler(handler, httpMessage));
    }

    private void callbackReceivedHandler(String handler, HttpMessage httpMessage) {
        try {
            OastRequest request = OastRequest.create(handler, httpMessage);
            extensionOast.getOastPanel().addCallbackRequest(request);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.warn("Failed to persist received callback:", e);
        }
    }

    private boolean hasView() {
        return extensionOast.getView() != null;
    }
}
