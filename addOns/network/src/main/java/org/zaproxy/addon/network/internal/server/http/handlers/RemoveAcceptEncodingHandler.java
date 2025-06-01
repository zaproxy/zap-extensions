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

import java.util.Objects;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A {@link HttpRequestHandler} that removes the {@code Accept-Encoding} header.
 *
 * @see #getEnabledInstance()
 */
public class RemoveAcceptEncodingHandler extends HttpRequestHandler {

    private static final RemoveAcceptEncodingHandler ALWAYS_ENABLED =
            new RemoveAcceptEncodingHandler(() -> true);

    /**
     * Gets the handler that always removes the header.
     *
     * @return the handler, never {@code null}.
     */
    public static RemoveAcceptEncodingHandler getEnabledInstance() {
        return ALWAYS_ENABLED;
    }

    private HandlerState status;

    /**
     * Constructs a {@code RemoveAcceptEncodingHandler} with the given state provider.
     *
     * @param state the state provider.
     * @throws NullPointerException if the given state provider is {@code null}.
     */
    public RemoveAcceptEncodingHandler(HandlerState state) {
        this.status = Objects.requireNonNull(state);
    }

    @Override
    protected void handleRequest(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!status.isEnabled()) {
            return;
        }

        String encoding = msg.getRequestHeader().getHeader(HttpHeader.ACCEPT_ENCODING);
        if (encoding == null) {
            return;
        }

        msg.getRequestHeader().setHeader(HttpHeader.ACCEPT_ENCODING, null);
    }
}
