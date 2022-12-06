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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpInputStream;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpOutputStream;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.network.HttpRequestBody;

/** Handles API requests by calling the {@link API}. */
public class ZapApiHandler implements HttpMessageHandler {

    private static final Logger LOGGER = LogManager.getLogger(ZapApiHandler.class);

    private HandlerState state;

    /**
     * Constructs a {@code ZapApiHandler} with the given state provider.
     *
     * @param state the state provider.
     * @throws NullPointerException if the given state provider is {@code null}.
     */
    public ZapApiHandler(HandlerState state) {
        this.state = Objects.requireNonNull(state);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (ctx.isFromClient()) {
            handleRequest(ctx, msg);
        }
    }

    private void handleRequest(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!state.isEnabled()) {
            return;
        }

        HttpRequestHeader requestHeader = msg.getRequestHeader();
        if (HttpRequestHeader.CONNECT.equalsIgnoreCase(requestHeader.getMethod())) {
            return;
        }

        try {
            handleApiRequest(ctx, msg);
        } catch (Exception e) {
            LOGGER.error("An error occurred while handling an API request:", e);
            ctx.close();
        }
    }

    private static void handleApiRequest(HttpMessageHandlerContext ctx, HttpMessage msg)
            throws IOException {
        HttpRequestHeader requestHeader = msg.getRequestHeader();
        HttpRequestBody reqBody = msg.getRequestBody();

        InputStream is = new ByteArrayInputStream(reqBody.getBytes());
        Socket socket =
                new Socket() {
                    @Override
                    public InputStream getInputStream() throws IOException {
                        return is;
                    }
                };
        HttpInputStream httpIn = new HttpInputStream(socket);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        HttpOutputStream httpOut = new HttpOutputStream(os);

        HttpMessage apiResponse =
                API.getInstance()
                        .handleApiRequest(requestHeader, httpIn, httpOut, ctx.isRecursive());

        if (apiResponse != null) {
            if (apiResponse.getRequestHeader().isEmpty()) {
                ctx.close();
                return;
            }

            msg.setResponseHeader(apiResponse.getResponseHeader());
            msg.setResponseBody(apiResponse.getResponseBody());

            ctx.overridden();
        }
    }
}
