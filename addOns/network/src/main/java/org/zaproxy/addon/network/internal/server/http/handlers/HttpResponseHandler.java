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

import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** A {@link HttpMessageHandler} that's interested only in HTTP responses. */
public abstract class HttpResponseHandler extends HttpIncludedMessageHandler {

    @Override
    protected final void handleMessage0(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!ctx.isFromClient()) {
            handleResponse(ctx, msg);
        }
    }

    /**
     * Handles the given HTTP response.
     *
     * @param ctx the current handling context.
     * @param msg the HTTP response received.
     */
    protected abstract void handleResponse(HttpMessageHandlerContext ctx, HttpMessage msg);
}
