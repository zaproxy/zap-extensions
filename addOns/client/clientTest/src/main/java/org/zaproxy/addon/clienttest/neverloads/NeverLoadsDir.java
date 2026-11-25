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
package org.zaproxy.addon.clienttest.neverloads;

import org.zaproxy.addon.clienttest.DelayedPage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.dev.streaming.StreamPage;

public class NeverLoadsDir extends TestDirectory {

    /** Longer than the default Selenium page load timeout of 5 minutes. */
    public static final long HANG_MS = 600_000;

    private static final long INTERVAL_MS = 1000;

    public NeverLoadsDir(TestProxyServer server, String name) {
        super(server, name);
        // The document never completes
        this.addPage(new DelayedPage(server, "hang", "hang.html", "text/html", HANG_MS, HANG_MS));
        // A script, used by subresource.html, which never completes
        this.addPage(
                new DelayedPage(
                        server,
                        "hang-script",
                        "hang-script.js",
                        "text/javascript",
                        HANG_MS,
                        HANG_MS));
        // Streamed responses, which are open for as long as the delayed pages above
        // A document which keeps trickling in
        this.addPage(
                new StreamPage(
                        server,
                        "trickle",
                        "text/html",
                        "<!DOCTYPE html><html><body><h1>Trickling document</h1>"
                                + "<p><a href=\"canary.html\">Canary</a></p>\n",
                        i -> "<span>.</span>\n",
                        INTERVAL_MS,
                        HANG_MS,
                        HANG_MS));
        // Server-sent events which never end
        this.addPage(
                new StreamPage(
                        server,
                        "sse",
                        "text/event-stream",
                        ": connected\n\n",
                        i -> "data: " + i + "\n\n",
                        INTERVAL_MS,
                        HANG_MS,
                        HANG_MS));
        // A script which starts but is never finished, nothing more is sent
        this.addPage(
                new StreamPage(
                        server,
                        "silent.js",
                        "text/javascript",
                        "/* never finished\n",
                        i -> "",
                        INTERVAL_MS,
                        HANG_MS,
                        HANG_MS));
    }
}
