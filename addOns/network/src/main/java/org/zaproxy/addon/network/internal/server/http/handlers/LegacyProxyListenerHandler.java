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
package org.zaproxy.addon.network.internal.server.http.handlers;

import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ArrangeableProxyListener;
import org.parosproxy.paros.core.proxy.ConnectRequestProxyListener;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.core.proxy.ProxyServer;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.PersistentConnectionListener;
import org.zaproxy.zap.ZapGetMethod;

/**
 * Handler that notifies core proxy listeners.
 *
 * <p>Notifies the following listeners:
 *
 * <ul>
 *   <li>{@link ConnectRequestProxyListener}
 *   <li>{@link OverrideMessageProxyListener}
 *   <li>{@link ProxyListener}
 * </ul>
 *
 * It also exposes the {@link PersistentConnectionListener}.
 */
public class LegacyProxyListenerHandler extends ProxyServer implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(LegacyProxyListenerHandler.class);

    private final List<ConnectRequestProxyListener> connectRequestProxyListeners;
    private final List<OverrideMessageProxyListener> overrideMessageProxyListeners;
    private final List<ProxyListener> proxyListeners;
    private final List<PersistentConnectionListener> persistentConnectionListeners;
    private final Comparator<ArrangeableProxyListener> listenersComparator;

    /** Constructs a {@code LegacyProxyListenerHandler} with no listeners. */
    public LegacyProxyListenerHandler() {
        connectRequestProxyListeners = Collections.synchronizedList(new ArrayList<>());
        overrideMessageProxyListeners = Collections.synchronizedList(new ArrayList<>());
        proxyListeners = Collections.synchronizedList(new ArrayList<>());
        persistentConnectionListeners = Collections.synchronizedList(new ArrayList<>());

        listenersComparator =
                (o1, o2) ->
                        Integer.compare(
                                o1.getArrangeableListenerOrder(), o2.getArrangeableListenerOrder());
    }

    @Override
    public void addConnectRequestProxyListener(ConnectRequestProxyListener listener) {
        connectRequestProxyListeners.add(listener);
    }

    @Override
    public void removeConnectRequestProxyListener(ConnectRequestProxyListener listener) {
        connectRequestProxyListeners.remove(listener);
    }

    @Override
    public void addOverrideMessageProxyListener(OverrideMessageProxyListener listener) {
        overrideMessageProxyListeners.add(listener);
        Collections.sort(overrideMessageProxyListeners, listenersComparator);
    }

    @Override
    public void removeOverrideMessageProxyListener(OverrideMessageProxyListener listener) {
        overrideMessageProxyListeners.remove(listener);
    }

    @Override
    public void addProxyListener(ProxyListener listener) {
        proxyListeners.add(listener);
        Collections.sort(proxyListeners, listenersComparator);
    }

    @Override
    public void removeProxyListener(ProxyListener listener) {
        proxyListeners.remove(listener);
    }

    @Override
    public void addPersistentConnectionListener(PersistentConnectionListener listener) {
        persistentConnectionListeners.add(listener);
        Collections.sort(persistentConnectionListeners, listenersComparator);
    }

    @Override
    public void removePersistentConnectionListener(PersistentConnectionListener listener) {
        persistentConnectionListeners.remove(listener);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage message) {
        if (ctx.isExcluded()) {
            return;
        }

        boolean request = ctx.isFromClient();
        if (HttpRequestHeader.CONNECT.equals(message.getRequestHeader().getMethod())) {
            if (!request) {
                return;
            }

            synchronized (connectRequestProxyListeners) {
                for (ConnectRequestProxyListener listener : connectRequestProxyListeners) {
                    handleErrors(
                            () -> {
                                listener.receivedConnectRequest(message);
                                return null;
                            },
                            null);
                }
            }
            return;
        }

        synchronized (overrideMessageProxyListeners) {
            boolean overridden = false;
            for (OverrideMessageProxyListener listener : overrideMessageProxyListeners) {
                if (request) {
                    overridden =
                            handleErrors(() -> listener.onHttpRequestSend(message), overridden);
                } else {
                    overridden =
                            handleErrors(
                                    () -> listener.onHttpResponseReceived(message), overridden);
                }

                if (overridden) {
                    ctx.overridden();
                    return;
                }
            }
        }

        synchronized (proxyListeners) {
            boolean forward = true;
            for (ProxyListener listener : proxyListeners) {
                if (request) {
                    forward = handleErrors(() -> listener.onHttpRequestSend(message), forward);
                } else {
                    forward = handleErrors(() -> listener.onHttpResponseReceive(message), forward);
                }

                if (!forward) {
                    ctx.close();
                    return;
                }
            }
        }
    }

    private static <T> T handleErrors(Callable<T> runnable, T fallbackValue) {
        try {
            return runnable.call();
        } catch (Throwable e) {
            LOGGER.error("An error occurred while notifying a listener:", e);
        }
        return fallbackValue;
    }

    /**
     * Notifies the {@code PersistentConnectionListener}s.
     *
     * @param message the message.
     * @param inSocket the connection from the client.
     * @param method the method used to send the message.
     * @return {@code true} if the connection should be kept open, {@code false} otherwise.
     */
    public boolean notifyPersistentConnectionListener(
            HttpMessage message, Socket inSocket, ZapGetMethod method) {
        synchronized (persistentConnectionListeners) {
            for (PersistentConnectionListener listener : persistentConnectionListeners) {
                if (handleErrors(
                        () -> listener.onHandshakeResponse(message, inSocket, method), false)) {
                    return true;
                }
            }
        }
        return false;
    }
}
