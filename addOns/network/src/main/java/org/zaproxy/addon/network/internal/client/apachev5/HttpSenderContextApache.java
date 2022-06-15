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

import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.util.TimeValue;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.network.internal.client.BaseHttpSenderContext;

/** A {@link BaseHttpSenderContext} for {@link HttpSenderApache}. */
public class HttpSenderContextApache extends BaseHttpSenderContext {

    enum CookieUsage {
        IGNORE,
        GLOBAL,
        LOCAL
    }

    private static final TimeValue RETRY_INTERVAL = TimeValue.ofSeconds(0L);

    private HttpRequestRetryStrategy requestRetryStrategy;
    private CookieUsage cookieUsage;
    private CookieStore localCookieStore;

    public HttpSenderContextApache(HttpSender parent, int initiator) {
        super(parent, initiator);
    }

    @Override
    public void setMaxRetriesOnIoError(int max) {
        super.setMaxRetriesOnIoError(max);

        requestRetryStrategy =
                new DefaultHttpRequestRetryStrategy(max, RETRY_INTERVAL) {
                    @Override
                    protected boolean handleAsIdempotent(HttpRequest request) {
                        return true;
                    }
                };
    }

    @Override
    public void setUseGlobalState(boolean use) {
        super.setUseGlobalState(use);
        checkCookieState();
    }

    @Override
    public void setUseCookies(boolean use) {
        super.setUseCookies(use);
        checkCookieState();
    }

    HttpRequestRetryStrategy getRequestRetryStrategy() {
        return requestRetryStrategy;
    }

    CookieUsage getCookieUsage() {
        return cookieUsage;
    }

    CookieStore getLocalCookieStore() {
        return localCookieStore;
    }

    private void checkCookieState() {
        if (!isUseCookies()) {
            cookieUsage = CookieUsage.IGNORE;
            resetLocalCookieStore();
            return;
        }

        if (isUseGlobalState()) {
            cookieUsage = CookieUsage.GLOBAL;
            return;
        }

        cookieUsage = CookieUsage.LOCAL;
        resetLocalCookieStore();
    }

    private void resetLocalCookieStore() {
        localCookieStore = new BasicCookieStore();
    }
}
