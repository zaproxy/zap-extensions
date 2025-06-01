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
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.server.http.LocalServerConfig;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.extension.api.API;

/**
 * A {@link HttpRequestHandler} that rewrites the requests to the ZAP API address, if the request is
 * a known alias.
 *
 * @see LocalServerConfig#isAlias(HttpRequestHeader)
 */
public class AliasApiRewriteHandler extends HttpRequestHandler {

    private static final Logger LOGGER = LogManager.getLogger(AliasApiRewriteHandler.class);

    private LocalServerConfig serverConfig;

    /**
     * Constructs an {@code AliasApiRewriteHandler} with the given server configuration.
     *
     * @param serverConfig the server configuration.
     * @throws NullPointerException if the given configuration is {@code null}.
     */
    public AliasApiRewriteHandler(LocalServerConfig serverConfig) {
        this.serverConfig = Objects.requireNonNull(serverConfig);
    }

    @Override
    protected void handleRequest(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!serverConfig.isApiEnabled()) {
            return;
        }

        HttpRequestHeader requestHeader = msg.getRequestHeader();
        if (HttpRequestHeader.CONNECT.equalsIgnoreCase(requestHeader.getMethod())) {
            return;
        }

        if (serverConfig.isAlias(requestHeader)) {
            try {
                requestHeader.getURI().setEscapedAuthority(API.API_DOMAIN);
                requestHeader.setHeader(HttpRequestHeader.HOST, API.API_DOMAIN);
            } catch (URIException e) {
                LOGGER.warn("Failed to set valid authority: {}", API.API_DOMAIN, e);
            }
        }
    }
}
