/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.clienttest.slowload;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * Responds after the number of milliseconds given by the {@code delay} parameter. When the page has
 * loaded it stores the time in the {@code localStorage} item {@code slowLoadedAt}.
 */
public class SlowLoadPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(SlowLoadPage.class);

    static final String DELAY_PARAM = "delay";
    static final long DEFAULT_DELAY_MS = 3000;
    static final long MAX_DELAY_MS = 30000;

    public SlowLoadPage(TestProxyServer server) {
        super(server, "page");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        long delay = getDelay(msg.getRequestHeader().getURI().getEscapedQuery());
        LOGGER.debug("Slow load page request, delaying by {}ms", delay);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        String body = this.getServer().getTextFile(this.getParent(), "page.html");
        body = body.replace("<!-- DELAY -->", Long.toString(delay));
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            "text/html", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Gets the delay from the given query.
     *
     * @param query the query of the request, might be {@code null}.
     * @return the delay in milliseconds, between 0 and {@link #MAX_DELAY_MS}, the default if it is
     *     not specified or invalid.
     */
    static long getDelay(String query) {
        if (query == null) {
            return DEFAULT_DELAY_MS;
        }
        for (String param : query.split("&")) {
            if (param.startsWith(DELAY_PARAM + "=")) {
                try {
                    long delay = Long.parseLong(param.substring(DELAY_PARAM.length() + 1));
                    return Math.max(0, Math.min(delay, MAX_DELAY_MS));
                } catch (NumberFormatException e) {
                    return DEFAULT_DELAY_MS;
                }
            }
        }
        return DEFAULT_DELAY_MS;
    }
}
