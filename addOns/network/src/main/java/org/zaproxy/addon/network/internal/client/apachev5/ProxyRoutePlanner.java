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

import org.apache.hc.client5.http.impl.routing.DefaultRoutePlanner;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.HttpProxy;

/** A {@link DefaultRoutePlanner} that proxies through the configured HTTP proxy. */
public class ProxyRoutePlanner extends DefaultRoutePlanner {

    private final ConnectionOptions options;

    public ProxyRoutePlanner(ConnectionOptions options) {
        super(null);

        this.options = options;
    }

    @Override
    protected HttpHost determineProxy(HttpHost target, HttpContext context) {
        HttpProxy proxy = options.getHttpProxy();
        if (!options.isUseHttpProxy(target.getHostName())) {
            return null;
        }
        return new HttpHost(target.getSchemeName(), proxy.getHost(), proxy.getPort());
    }
}
