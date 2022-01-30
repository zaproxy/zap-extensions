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

import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Handles a CONNECT received by a server.
 *
 * <p>It sets a successful response and it either {@link HttpMessageHandlerContext#overridden()
 * overrides} it or not, allowing other handlers to still be notified.
 *
 * @see #getSetAndOverrideInstance()
 * @see #getSetAndContinueInstance()
 */
public class ConnectReceivedHandler implements HttpMessageHandler {

    private static final ConnectReceivedHandler SET_AND_OVERRIDE = new ConnectReceivedHandler(true);
    private static final ConnectReceivedHandler SET_AND_CONTINUE =
            new ConnectReceivedHandler(false);

    /**
     * Gets the handler that sets the response and overrides it, preventing other handlers from
     * being notified.
     *
     * @return the handler, never {@code null}.
     */
    public static ConnectReceivedHandler getSetAndOverrideInstance() {
        return SET_AND_OVERRIDE;
    }

    /**
     * Gets the handler that sets the response and does not override it, allowing other handlers to
     * be notified.
     *
     * @return the handler, never {@code null}.
     */
    public static ConnectReceivedHandler getSetAndContinueInstance() {
        return SET_AND_CONTINUE;
    }

    private static final String CONNECT_HTTP_200 = "HTTP/1.1 200 Connection established";

    private boolean override;

    private ConnectReceivedHandler(boolean override) {
        this.override = override;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!ctx.isFromClient()) {
            return;
        }

        HttpRequestHeader request = msg.getRequestHeader();
        if (!HttpRequestHeader.CONNECT.equalsIgnoreCase(request.getMethod())) {
            return;
        }

        msg.setTimeSentMillis(System.currentTimeMillis());
        try {
            msg.setResponseHeader(CONNECT_HTTP_200);
        } catch (HttpMalformedHeaderException ignore) {
            // Setting valid header.
        }

        if (override) {
            ctx.overridden();
        }
    }
}
