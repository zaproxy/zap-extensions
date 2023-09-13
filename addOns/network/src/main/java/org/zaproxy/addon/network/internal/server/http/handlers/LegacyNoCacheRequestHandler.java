/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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

import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;

/**
 * Legacy undocumented behaviour migrated from core that changes the proxied messages by removing
 * cache related headers.
 */
public class LegacyNoCacheRequestHandler extends HttpRequestHandler {

    private static final Logger LOGGER = LogManager.getLogger(LegacyNoCacheRequestHandler.class);

    private final Model model;
    private final ConnectionOptions options;

    public LegacyNoCacheRequestHandler(Model model, ConnectionOptions options) {
        this.model = model;
        this.options = options;
    }

    @Override
    protected void handleRequest(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!options.isLegacyRemoveCacheHeaders()) {
            return;
        }

        if (HttpRequestHeader.CONNECT.equals(msg.getRequestHeader().getMethod())) {
            return;
        }

        onHttpRequestSend(msg);
    }

    // Implementation migrated verbatim from core class ProxyListenerLog (v2.13.0).
    private boolean onHttpRequestSend(HttpMessage msg) {
        //	    if (msg.getRequestHeader().isImage()) {
        //	        return;
        //	    }

        try {
            StructuralNode node = SessionStructure.find(model, msg);
            if (node != null) {
                HttpMessage existingMsg = node.getHistoryReference().getHttpMessage();
                // check if a msg of the same type exist
                if (existingMsg != null && !existingMsg.getResponseHeader().isEmpty()) {
                    if (HttpStatusCode.isSuccess(existingMsg.getResponseHeader().getStatusCode())) {
                        // exist, no modification necessary
                        return true;
                    }
                }
            }
        } catch (URIException | DatabaseException | HttpMalformedHeaderException e) {
            LOGGER.warn("Failed to check if message already exists:", e);
        }

        // if not, make sure a new copy will be obtained
        if (msg.getRequestHeader().getHeader(HttpHeader.IF_MODIFIED_SINCE) != null) {
            msg.getRequestHeader().setHeader(HttpHeader.IF_MODIFIED_SINCE, null);
        }

        if (msg.getRequestHeader().getHeader(HttpHeader.IF_NONE_MATCH) != null) {
            msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, null);
        }
        return true;
    }
}
