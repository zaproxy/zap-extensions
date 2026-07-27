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
import java.net.Socket;
import java.net.SocketTimeoutException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EventStreamListener implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger(EventStreamListener.class);

    private EventStreamProxy proxy;
    private BufferedReader reader;
    private Socket socket;

    public EventStreamListener(EventStreamProxy proxy, BufferedReader reader, Socket socket) {
        this.proxy = proxy;
        this.reader = reader;
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            String firstEventLine;
            String line;
            while ((firstEventLine = readLineWithTimeout()) != null) {
                if (firstEventLine.equals("")) {
                    // blank line before any event data (e.g. keep-alive) - not an event
                    continue;
                }

                StringBuilder rawEvent = new StringBuilder(firstEventLine);
                while ((line = readLineWithTimeout()) != null) {
                    if (line.equals("")) {
                        // event finishes on newline => trigger dispatch
                        proxy.processEvent(rawEvent.toString());
                        break;
                    }
                    rawEvent.append("\n");
                    rawEvent.append(line);
                }
            }
        } catch (IOException e) {
            LOGGER.debug("I/O exception while handling Server-Sent Event:", e);
        } catch (Exception e) {
            LOGGER.warn(
                    "An exception occurred while reading Server-Sent Events: {}",
                    e.getMessage(),
                    e);
        } finally {
            this.proxy.stop();
        }
    }

    private String readLineWithTimeout() throws IOException {
        while (true) {
            try {
                return reader.readLine();
            } catch (SocketTimeoutException e) {
                LOGGER.debug("Socket timed out waiting for Server-Sent Event, continuing.");
            }
        }
    }

    public void close() throws IOException {
        socket.close();
    }
}
