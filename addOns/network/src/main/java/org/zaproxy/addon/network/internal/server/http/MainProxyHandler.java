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
package org.zaproxy.addon.network.internal.server.http;

import io.netty.channel.ChannelHandlerContext;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.handlers.LegacySocketAdapter;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.zap.ZapGetMethod;

/**
 * A {@link MainServerHandler} for proxies, attempts to keep the connection open for other protocols
 * (e.g. WebSocket, SSE).
 */
public class MainProxyHandler extends MainServerHandler {

    private final LegacyProxyListenerHandler legacyHandler;

    /**
     * Constructs a {@code HttpMessageServerBridge} with the given legacy handler and message
     * handlers.
     *
     * @param legacyHandler the legacy listeners.
     * @param handlers the message handlers.
     * @throws NullPointerException if any of the parameters is {@code null}.
     */
    public MainProxyHandler(
            LegacyProxyListenerHandler legacyHandler, List<HttpMessageHandler> handlers) {
        super(handlers);

        this.legacyHandler = Objects.requireNonNull(legacyHandler);
    }

    @Override
    protected boolean postWriteResponse(ChannelHandlerContext ctx, HttpMessage msg) {
        if (msg.getResponseHeader().getStatusCode() != 101 && !msg.isEventStream()) {
            return false;
        }

        LegacySocketAdapter passThroughAdapter = new LegacySocketAdapter(ctx.channel());
        ZapGetMethod method = (ZapGetMethod) msg.getUserObject();
        if (method == null) {
            method = new ZapGetMethod();
            method.setUpgradedSocket(passThroughAdapter.getSocket());
            try {
                method.setUpgradedInputStream(passThroughAdapter.getSocket().getInputStream());
            } catch (IOException ignore) {
            }
        }
        boolean keepConnectionOpen =
                legacyHandler.notifyPersistentConnectionListener(
                        msg, passThroughAdapter.getSocket(), method);
        if (keepConnectionOpen) {
            return true;
        }

        // No add-on to process the data.
        close(ctx);
        return true;
    }
}
