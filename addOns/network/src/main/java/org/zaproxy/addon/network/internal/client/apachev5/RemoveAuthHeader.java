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
package org.zaproxy.addon.network.internal.client.apachev5;

import java.io.IOException;
import java.util.Map;
import org.apache.hc.client5.http.auth.AuthExchange;
import org.apache.hc.client5.http.auth.AuthExchange.State;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.HttpProxy;

/**
 * A {@link HttpRequestInterceptor} that removes the proxy/host authorization headers if required.
 */
public class RemoveAuthHeader implements HttpRequestInterceptor {

    private static final Logger LOGGER = LogManager.getLogger(RemoveAuthHeader.class);

    static final String ATTR_NAME = "zap.auth.remove-user-headers";
    private static final String PROXY_HEADER_PROCESSED = ATTR_NAME + ".proxy.processed";
    private static final String HOST_HEADER_PROCESSED = ATTR_NAME + ".host.processed";

    private final ConnectionOptions connectionOptions;

    public RemoveAuthHeader(ConnectionOptions connectionOptions) {
        this.connectionOptions = connectionOptions;
    }

    @Override
    public void process(HttpRequest request, EntityDetails entity, HttpContext context)
            throws HttpException, IOException {
        if (!isSet(context, ATTR_NAME)) {
            return;
        }

        HttpClientContext clientContext = HttpClientContext.adapt(context);
        Map<HttpHost, AuthExchange> exchanges = clientContext.getAuthExchanges();
        if (exchanges.isEmpty()) {
            return;
        }

        for (Map.Entry<HttpHost, AuthExchange> entry : exchanges.entrySet()) {
            HttpHost host = entry.getKey();
            AuthExchange exchange = entry.getValue();
            if (exchange.getState() == State.CHALLENGED) {
                if (isProxy(host)) {
                    process(
                            clientContext,
                            PROXY_HEADER_PROCESSED,
                            request,
                            HttpHeaders.PROXY_AUTHORIZATION);
                } else {
                    process(
                            clientContext,
                            HOST_HEADER_PROCESSED,
                            request,
                            HttpHeaders.AUTHORIZATION);
                }
            }
        }
    }

    private static void process(
            HttpClientContext context,
            String attributeName,
            HttpRequest request,
            String headerName) {
        if (isSet(context, attributeName)) {
            return;
        }

        context.setAttribute(attributeName, Boolean.TRUE);
        if (request.containsHeader(headerName)) {
            LOGGER.debug("{} removing existing {} header", context.getExchangeId(), headerName);
            request.removeHeaders(headerName);
        }
    }

    private boolean isProxy(HttpHost host) {
        HttpProxy proxy = connectionOptions.getHttpProxy();
        return proxy.getHost().equals(host.getHostName()) && proxy.getPort() == host.getPort();
    }

    private static boolean isSet(HttpContext context, String attributeName) {
        return Boolean.TRUE.equals(context.getAttribute(attributeName));
    }
}
