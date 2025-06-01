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

import org.apache.hc.client5.http.RouteInfo;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.CookieSpecFactory;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.config.Lookup;

/** A {@link HttpClientContext} with enhanced behaviour. */
public class ZapHttpClientContext extends HttpClientContext {

    private int requestCount;

    private CookieStore cookieStore;
    private Lookup<CookieSpecFactory> registry;
    private RouteInfo route;
    private RequestConfig config;
    private HttpRequest request;

    ZapHttpClientContext() {}

    void increaseRequestCount() {
        requestCount++;
    }

    public int getRequestCount() {
        return requestCount;
    }

    boolean hasCookieSetup() {
        return cookieStore != null;
    }

    public void setCookieSetup(
            CookieStore cookieStore,
            Lookup<CookieSpecFactory> registry,
            RouteInfo route,
            RequestConfig config,
            HttpRequest request) {
        this.cookieStore = cookieStore;
        this.registry = registry;
        this.route = route;
        this.config = config;
        this.request = request;
    }

    HttpRequest getFirstRequest() {
        return request;
    }

    HttpClientContext getCookieContext() {
        HttpClientContext context = new HttpClientContext();
        context.setCookieStore(cookieStore);
        context.setCookieSpecRegistry(registry);
        context.setAttribute(HttpClientContext.HTTP_ROUTE, route);
        context.setRequestConfig(config);
        return context;
    }
}
