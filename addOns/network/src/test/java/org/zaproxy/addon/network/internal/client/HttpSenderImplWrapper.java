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
package org.zaproxy.addon.network.internal.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.file.Path;
import org.mockito.invocation.InvocationOnMock;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.client.core.HttpSenderContext;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

public class HttpSenderImplWrapper<T extends HttpSenderContext> {

    private static final HttpRequestConfig NO_REDIRECTS = HttpRequestConfig.builder().build();
    private static final HttpRequestConfig FOLLOW_REDIRECTS =
            HttpRequestConfig.builder().setFollowRedirects(true).build();

    private HttpSender parent;

    private CloseableHttpSenderImpl<T> impl;

    private final T ctx;

    public HttpSenderImplWrapper(CloseableHttpSenderImpl<T> impl, int initiator) {
        this.impl = impl;
        parent = mock(HttpSender.class);
        try {
            doAnswer(this::send).when(parent).sendAndReceive(any());
            doAnswer(this::send).when(parent).sendAndReceive(any(), anyBoolean());
            doAnswer(this::send).when(parent).sendAndReceive(any(), any(HttpRequestConfig.class));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ctx = impl.createContext(parent, initiator);

        setUseGlobalState(true);
        setUseCookies(true);
    }

    private Void send(InvocationOnMock invocation) throws IOException {
        int argCount = invocation.getArguments().length;
        HttpMessage msg = invocation.getArgument(0);
        if (argCount == 1) {
            sendAndReceive(msg);
            return null;
        }

        Object secondArg = invocation.getArgument(1);
        if (secondArg instanceof Boolean) {
            sendAndReceive(msg, (Boolean) secondArg);
            return null;
        }

        sendAndReceive(msg, (HttpRequestConfig) secondArg);
        return null;
    }

    public HttpSender getParent() {
        return parent;
    }

    public void addListener(HttpSenderListener listener) {
        impl.addListener(listener);
    }

    public void removeListener(HttpSenderListener listener) {
        impl.removeListener(listener);
    }

    public void close() {
        impl.close();
    }

    public void setUseGlobalState(boolean enableGlobalState) {
        ctx.setUseGlobalState(enableGlobalState);
    }

    public boolean isGlobalStateEnabled() {
        return impl.isGlobalStateEnabled();
    }

    public void setUseCookies(boolean shouldUseCookies) {
        ctx.setUseCookies(shouldUseCookies);
    }

    public void sendAndReceive(HttpMessage message, Path file) throws IOException {
        impl.sendAndReceive(ctx, null, message, file);
    }

    public void sendAndReceive(HttpMessage msg) throws IOException {
        impl.sendAndReceive(ctx, null, msg, null);
    }

    public void sendAndReceive(HttpMessage msg, boolean isFollowRedirect) throws IOException {
        impl.sendAndReceive(ctx, isFollowRedirect ? FOLLOW_REDIRECTS : NO_REDIRECTS, msg, null);
    }

    public User getUser(HttpMessage msg) {
        return ctx.getUser(msg);
    }

    public void setFollowRedirect(boolean followRedirect) {
        ctx.setFollowRedirects(followRedirect);
    }

    public void setUser(User user) {
        ctx.setUser(user);
    }

    public void setRemoveUserDefinedAuthHeaders(boolean removeHeaders) {
        ctx.setRemoveUserDefinedAuthHeaders(removeHeaders);
    }

    public void setMaxRetriesOnIOError(int retries) {
        ctx.setMaxRetriesOnIoError(retries);
    }

    public void setMaxRedirects(int maxRedirects) {
        ctx.setMaxRedirects(maxRedirects);
    }

    public void sendAndReceive(HttpMessage message, HttpRequestConfig requestConfig)
            throws IOException {
        impl.sendAndReceive(ctx, requestConfig, message, null);
    }
}
