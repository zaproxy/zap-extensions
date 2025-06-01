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
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;

/**
 * A {@link HttpRequestRetryStrategy} that retries with the strategy available in the context,
 * otherwise with the default strategy.
 *
 * @see DefaultHttpRequestRetryStrategy#INSTANCE
 */
public class RequestRetryStrategy implements HttpRequestRetryStrategy {

    static final String CUSTOM_RETRY = "zap.request-retry-strategy";

    private static final HttpRequestRetryStrategy DEFAULT_RETRY =
            DefaultHttpRequestRetryStrategy.INSTANCE;

    @Override
    public boolean retryRequest(
            HttpRequest request, IOException exception, int execCount, HttpContext context) {
        return getRetryStrategy(context).retryRequest(request, exception, execCount, context);
    }

    private static HttpRequestRetryStrategy getRetryStrategy(HttpContext context) {
        HttpRequestRetryStrategy retryStrategy =
                (HttpRequestRetryStrategy) context.getAttribute(CUSTOM_RETRY);
        if (retryStrategy == null) {
            return DEFAULT_RETRY;
        }
        return retryStrategy;
    }

    @Override
    public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
        return getRetryStrategy(context).retryRequest(response, execCount, context);
    }

    @Override
    public TimeValue getRetryInterval(HttpResponse response, int execCount, HttpContext context) {
        return getRetryStrategy(context).getRetryInterval(response, execCount, context);
    }
}
