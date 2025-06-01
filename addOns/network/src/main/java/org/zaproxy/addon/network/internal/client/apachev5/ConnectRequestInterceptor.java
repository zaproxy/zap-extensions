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

import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.zaproxy.addon.network.ConnectionOptions;

/**
 * A {@link HttpRequestInterceptor} that adds the configured user-agent.
 *
 * <p>It's expected to be used just for automatic CONNECT requests.
 */
public class ConnectRequestInterceptor implements HttpRequestInterceptor {

    private final ConnectionOptions connectionOptions;

    public ConnectRequestInterceptor(ConnectionOptions connectionOptions) {
        this.connectionOptions = connectionOptions;
    }

    @Override
    public void process(HttpRequest request, EntityDetails entity, HttpContext context) {
        String userAgent = connectionOptions.getDefaultUserAgent();
        if (userAgent != null && !userAgent.isEmpty()) {
            request.addHeader(HttpHeaders.USER_AGENT, userAgent);
        }
    }
}
