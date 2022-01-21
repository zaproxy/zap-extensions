/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.sse;

import java.io.BufferedReader;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.ZapGetMethod;

public class EventStreamListener implements Runnable {

    private static final Logger logger = LogManager.getLogger(EventStreamListener.class);

    private EventStreamProxy proxy;
    private BufferedReader reader;
    private ZapGetMethod method;

    public EventStreamListener(EventStreamProxy proxy, BufferedReader reader, ZapGetMethod method) {
        this.proxy = proxy;
        this.reader = reader;
        this.method = method;
    }

    @Override
    public void run() {
        try {
            String firstEventLine;
            String line;
            while ((firstEventLine = reader.readLine()) != null) {
                if (firstEventLine.equals("")) {
                    // TODO: should we really fire an empty event?
                    proxy.processEvent("");
                }

                StringBuilder rawEvent = new StringBuilder(firstEventLine);
                while ((line = reader.readLine()) != null) {
                    if (line.equals("")) {
                        // event finishes on newline => trigger dispatch
                        proxy.processEvent(rawEvent.toString());
                        break;
                    }
                    rawEvent.append("\n");
                    rawEvent.append(line);
                }
            }
        } catch (Exception e) {
            // includes SocketException
            // no more reading possible
            logger.warn(
                    "An exception occurred while reading Server-Sent Events: {}",
                    e.getMessage(),
                    e);
        } finally {
            this.proxy.stop();
        }
    }

    public void close() throws IOException {
        method.abort();
    }
}
