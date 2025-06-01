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

import java.util.Collections;
import java.util.Objects;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A {@link HttpResponseHandler} that decodes a response.
 *
 * @see #getEnabledInstance()
 */
public class DecodeResponseHandler extends HttpResponseHandler {

    private static final DecodeResponseHandler ALWAYS_ENABLED =
            new DecodeResponseHandler(() -> true);

    /**
     * Gets the handler that always decodes the response.
     *
     * @return the handler, never {@code null}.
     */
    public static DecodeResponseHandler getEnabledInstance() {
        return ALWAYS_ENABLED;
    }

    private HandlerState state;

    /**
     * Constructs a {@code DecodeResponseHandler} with the given state provider.
     *
     * @param state the state provider.
     * @throws NullPointerException if the given state provider is {@code null}.
     */
    public DecodeResponseHandler(HandlerState state) {
        this.state = Objects.requireNonNull(state);
    }

    @Override
    public void handleResponse(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!state.isEnabled()) {
            return;
        }

        HttpBody body = msg.getResponseBody();
        if (body.getContentEncodings().isEmpty() || body.hasContentEncodingErrors()) {
            return;
        }

        body.setBody(body.getContent());
        body.setContentEncodings(Collections.emptyList());
        HttpHeader header = msg.getResponseHeader();
        header.setHeader(HttpHeader.CONTENT_ENCODING, null);
        if (header.getHeader(HttpHeader.CONTENT_LENGTH) != null) {
            header.setContentLength(body.length());
        }
    }
}
