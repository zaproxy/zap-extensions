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
package org.zaproxy.addon.dev.streaming;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.IntFunction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.ChunkedOutputStream;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A page which streams its response, a chunk at a time, for a limited time. For example for a
 * document which trickles in, a server-sent events stream, or a response which is held open without
 * sending anything.
 *
 * <p>The time between the chunks and how long the response is open for can be changed per request
 * with the {@code interval} (at least 1) and {@code duration} parameters, in milliseconds.
 */
public class StreamPage extends TestPage {

    private static final Logger LOGGER = LogManager.getLogger(StreamPage.class);

    public static final String INTERVAL_PARAM = "interval";
    public static final String DURATION_PARAM = "duration";

    private final String contentType;
    private final String preamble;
    private final IntFunction<String> chunks;
    private final long defaultIntervalMs;
    private final long defaultDurationMs;
    private final long maxDurationMs;

    /**
     * Constructs a page.
     *
     * @param server the test server.
     * @param name the name of the page.
     * @param contentType the content type of the response.
     * @param preamble what is written, with the headers, before the first interval.
     * @param chunks provides the chunk to write, given its index starting at 0, an empty chunk is
     *     not written.
     * @param defaultIntervalMs the default time between chunks.
     * @param defaultDurationMs the default time the response is open for.
     * @param maxDurationMs the maximum time the response is open for.
     */
    public StreamPage(
            TestProxyServer server,
            String name,
            String contentType,
            String preamble,
            IntFunction<String> chunks,
            long defaultIntervalMs,
            long defaultDurationMs,
            long maxDurationMs) {
        super(server, name);
        this.contentType = contentType;
        this.preamble = preamble;
        this.chunks = chunks;
        this.defaultIntervalMs = defaultIntervalMs;
        this.defaultDurationMs = defaultDurationMs;
        this.maxDurationMs = maxDurationMs;
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String query = msg.getRequestHeader().getURI().getEscapedQuery();
        long interval =
                Math.max(
                        1,
                        DevUtils.getLongParam(
                                query, INTERVAL_PARAM, defaultIntervalMs, maxDurationMs));
        long duration =
                DevUtils.getLongParam(query, DURATION_PARAM, defaultDurationMs, maxDurationMs);
        LOGGER.debug("Streaming {} for {}ms every {}ms", getName(), duration, interval);

        try {
            msg.setResponseHeader(TestProxyServer.getDefaultResponseHeader(contentType, 0));
            msg.getResponseHeader().setHeader(HttpHeader.CONTENT_LENGTH, null);
            msg.getResponseHeader().setHeader(HttpHeader.TRANSFER_ENCODING, "chunked");
            // Closing the stream ends the response and closes the connection.
            try (OutputStream out = new ChunkedOutputStream(ctx.streamingResponse(msg))) {
                write(out, preamble);

                long end = System.currentTimeMillis() + duration;
                for (int i = 0; System.currentTimeMillis() < end; i++) {
                    Thread.sleep(interval);
                    write(out, chunks.apply(i));
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (IOException e) {
            // Normally the client closing the connection.
            LOGGER.debug("Streaming {} ended: {}", getName(), e.toString());
        }
    }

    private static void write(OutputStream out, String chunk) throws IOException {
        if (!chunk.isEmpty()) {
            out.write(chunk.getBytes(StandardCharsets.UTF_8));
        }
    }
}
