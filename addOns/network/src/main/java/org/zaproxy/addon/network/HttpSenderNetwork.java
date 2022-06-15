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
package org.zaproxy.addon.network;

import java.io.Closeable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.client.CloseableHttpSenderImpl;
import org.zaproxy.addon.network.internal.client.core.HttpSenderContext;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

class HttpSenderNetwork<T extends HttpSenderContext> implements Closeable {

    private static final Logger LOGGER = LogManager.getLogger(HttpSenderNetwork.class);

    private final CloseableHttpSenderImpl<T> sender;
    private final Object implementation;
    private final Method setImpl;

    HttpSenderNetwork(ConnectionOptions connectionOptions, CloseableHttpSenderImpl<T> sender) {
        Objects.requireNonNull(connectionOptions);
        this.sender = Objects.requireNonNull(sender);

        try {
            Class<?> implClass = Class.forName("org.zaproxy.zap.network.HttpSenderImpl");
            Class<?>[] contextClass =
                    new Class<?>[] {Class.forName("org.zaproxy.zap.network.HttpSenderContext")};

            InvocationHandler invocationHandler =
                    (o, method, args) -> {
                        switch (method.getName()) {
                            case "isGlobalStateEnabled":
                                return connectionOptions.isUseGlobalHttpState();

                            case "addListener":
                                sender.addListener((HttpSenderListener) args[0]);
                                return null;

                            case "removeListener":
                                sender.removeListener((HttpSenderListener) args[0]);
                                return null;

                            case "createContext":
                                T context =
                                        sender.createContext((HttpSender) args[0], (int) args[1]);
                                return Proxy.newProxyInstance(
                                        getClass().getClassLoader(),
                                        contextClass,
                                        new ContextProxy(context));

                            case "sendAndReceive":
                                @SuppressWarnings("unchecked")
                                ContextProxy contextProxy =
                                        (ContextProxy) Proxy.getInvocationHandler(args[0]);
                                sender.sendAndReceive(
                                        contextProxy.getContext(),
                                        (HttpRequestConfig) args[1],
                                        (HttpMessage) args[2],
                                        (Path) args[3]);
                                return null;

                            default:
                                return null;
                        }
                    };

            implementation =
                    Proxy.newProxyInstance(
                            getClass().getClassLoader(),
                            new Class<?>[] {implClass},
                            invocationHandler);

            setImpl = HttpSender.class.getDeclaredMethod("setImpl", implClass);
            setHttpSenderImpl(implementation);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void setHttpSenderImpl(Object value) {
        try {
            setImpl.invoke(HttpSender.class, value);
        } catch (Exception e) {
            LOGGER.error("An error occurred while setting the HttpSender implementation:", e);
        }
    }

    void unload() {
        setHttpSenderImpl(null);
    }

    @Override
    public void close() {
        sender.close();
    }

    private class ContextProxy implements InvocationHandler {

        private final T context;

        ContextProxy(T context) {
            this.context = context;
        }

        T getContext() {
            return context;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            switch (method.getName()) {
                case "setUseGlobalState":
                    context.setUseGlobalState((boolean) args[0]);
                    return null;

                case "setUseCookies":
                    context.setUseCookies((boolean) args[0]);
                    return null;

                case "setFollowRedirects":
                    context.setFollowRedirects((boolean) args[0]);
                    return null;

                case "setMaxRedirects":
                    context.setMaxRedirects((int) args[0]);
                    return null;

                case "setMaxRetriesOnIoError":
                    context.setMaxRetriesOnIoError((int) args[0]);
                    return null;

                case "setRemoveUserDefinedAuthHeaders":
                    context.setRemoveUserDefinedAuthHeaders((boolean) args[0]);
                    return null;

                case "setUser":
                    context.setUser((User) args[0]);
                    return null;

                case "getUser":
                    return context.getUser((HttpMessage) args[0]);

                default:
                    return null;
            }
        }
    }
}
