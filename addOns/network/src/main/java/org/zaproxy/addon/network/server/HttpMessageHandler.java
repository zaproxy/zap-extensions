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
package org.zaproxy.addon.network.server;

import org.parosproxy.paros.network.HttpMessage;

/**
 * A handler of {@link HttpMessage}s, the request received by the client and the response from the
 * server.
 *
 * <p>The handlers are first notified for the request and then for the response, if any.
 *
 * @since 0.1.0
 * @see HttpMessageHandlerContext
 */
public interface HttpMessageHandler {

    /**
     * Handles the given {@code HttpMessage}.
     *
     * @param ctx the current handling context.
     * @param msg the message received.
     */
    void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg);
}
