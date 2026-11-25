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
package org.zaproxy.addon.clienttest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A page which only responds after the delay given by the {@code delay} parameter, in milliseconds.
 * The response is the given file of the directory, in which {@code <!-- DELAY -->} is replaced by
 * the delay.
 */
public class DelayedPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(DelayedPage.class);

    static final String DELAY_PARAM = "delay";

    private final String fileName;
    private final String contentType;
    private final long defaultDelayMs;
    private final long maxDelayMs;

    public DelayedPage(
            TestProxyServer server,
            String name,
            String fileName,
            String contentType,
            long defaultDelayMs,
            long maxDelayMs) {
        super(server, name);
        this.fileName = fileName;
        this.contentType = contentType;
        this.defaultDelayMs = defaultDelayMs;
        this.maxDelayMs = maxDelayMs;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        long delay =
                getDelay(
                        msg.getRequestHeader().getURI().getEscapedQuery(),
                        defaultDelayMs,
                        maxDelayMs);
        LOGGER.debug("Delayed page {} requested, delaying by {}ms", getName(), delay);
        try {
            Thread.sleep(delay);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        msg.setResponseBody(
                getServer()
                        .getTextFile(getParent(), fileName)
                        .replace("<!-- DELAY -->", Long.toString(delay)));
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            contentType, msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    /**
     * Gets the delay from the given query.
     *
     * @param query the query of the request, might be {@code null}.
     * @param defaultDelayMs the delay if it is not specified or invalid.
     * @param maxDelayMs the maximum delay.
     * @return the delay in milliseconds, between 0 and {@code maxDelayMs}.
     */
    static long getDelay(String query, long defaultDelayMs, long maxDelayMs) {
        return DevUtils.getLongParam(query, DELAY_PARAM, defaultDelayMs, maxDelayMs);
    }
}
