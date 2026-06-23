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
package org.zaproxy.addon.dev.rnd;

import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A dynamically generated site for testing spider scalability. The number of pages and links per
 * page are configured via a form at /rnd/simple. Pages are addressed as base-10 digit path
 * segments, e.g. /rnd/simple/4/9/9 for page 499 of a 500-page site.
 *
 * <p>Link structure: root links to pages 0..L-1; page P links to pages (P+1)*L..(P+2)*L-1 (if
 * valid), or back to root if all children would exceed the page count.
 */
public class SimpleDir extends TestDirectory {

    private static final Logger LOGGER = LogManager.getLogger(SimpleDir.class);
    private static final String PREFIX = "/rnd/simple";

    private int numPages = -1;
    private int numLinks = -1;

    public SimpleDir(TestProxyServer server) {
        super(server, "simple");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        try {
            String path = msg.getRequestHeader().getURI().getEscapedPath();
            String method = msg.getRequestHeader().getMethod();

            String subPath = path.substring(PREFIX.length());
            if (subPath.startsWith("/")) {
                subPath = subPath.substring(1);
            }
            if (subPath.endsWith("/")) {
                subPath = subPath.substring(0, subPath.length() - 1);
            }

            if (subPath.isEmpty()) {
                if (HttpRequestHeader.POST.equals(method)) {
                    handlePost(ctx, msg);
                } else {
                    handleRootGet(ctx, msg);
                }
            } else {
                handleGeneratedPage(ctx, msg, subPath);
            }
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void handlePost(HttpMessageHandlerContext ctx, HttpMessage msg)
            throws HttpMalformedHeaderException {
        String action = DevUtils.getFormParam(msg, "action");
        if ("reset".equals(action)) {
            String resetConfirm = DevUtils.getFormParam(msg, "resetConfirm");
            if ("RESET".equals(resetConfirm)) {
                numPages = -1;
                numLinks = -1;
            }
        } else if (numPages < 0) {
            String numPagesStr = DevUtils.getFormParam(msg, "numPages");
            String numLinksStr = DevUtils.getFormParam(msg, "numLinks");
            if (numPagesStr != null && numLinksStr != null) {
                try {
                    int pages = Integer.parseInt(numPagesStr);
                    int links = Integer.parseInt(numLinksStr);
                    if (pages > 0 && links > 0) {
                        numPages = pages;
                        numLinks = links;
                    }
                } catch (NumberFormatException e) {
                    // Invalid input - stay on form
                }
            }
        }
        handleRootGet(ctx, msg);
    }

    private void handleRootGet(HttpMessageHandlerContext ctx, HttpMessage msg)
            throws HttpMalformedHeaderException {
        String body;
        if (numPages < 0) {
            body =
                    """
                    <!DOCTYPE html>
                    <html>
                    <head><title>Random Simple Site</title></head>
                    <body>
                    <h1>Random Simple Site</h1>
                    <p>Configure this site to generate pages for spider testing.</p>
                    <form method="POST">
                    <table>
                    <tr><td>Number of pages:</td><td><input type="number" name="numPages" value="10"></td></tr>
                    <tr><td>Number of links:</td><td><input type="number" name="numLinks" value="5"></td></tr>
                    <tr><td colspan="2"><button type="submit">Generate</button></td></tr>
                    </table>
                    </form>
                    </body>
                    </html>
                    """;
        } else {
            StringBuilder links = new StringBuilder();
            int rootLinks = Math.min(numLinks, numPages);
            for (int i = 0; i < rootLinks; i++) {
                links.append("<li><a href=\"%s\">Page %d</a></li>\n".formatted(pagePath(i), i));
            }
            body =
                    """
                    <!DOCTYPE html>
                    <html>
                    <head><title>Random Simple Site</title></head>
                    <body>
                    <h1>Random Simple Site</h1>
                    <p>Pages: %d, Links per page: %d</p>
                    <ul>
                    %s</ul>
                    <hr>
                    <p>To reset, type RESET in the field below and click Reset.</p>
                    <form method="POST">
                    <input type="text" name="resetConfirm" placeholder="Type RESET">
                    <button type="submit" name="action" value="reset">Reset</button>
                    </form>
                    </body>
                    </html>
                    """
                            .formatted(numPages, numLinks, links);
        }
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8, msg.getResponseBody().length()));
    }

    private void handleGeneratedPage(HttpMessageHandlerContext ctx, HttpMessage msg, String subPath)
            throws HttpMalformedHeaderException {
        if (numPages < 0) {
            send404(msg);
            return;
        }

        int depth = getDepth(numPages);
        String[] parts = subPath.split("/");

        if (parts.length != depth) {
            send404(msg);
            return;
        }

        for (String part : parts) {
            if (part.length() != 1 || !Character.isDigit(part.charAt(0))) {
                send404(msg);
                return;
            }
        }

        int pageNum = 0;
        for (String part : parts) {
            pageNum = pageNum * 10 + (part.charAt(0) - '0');
        }

        if (pageNum >= numPages) {
            send404(msg);
            return;
        }

        showPage(msg, pageNum);
    }

    private void showPage(HttpMessage msg, int pageNum) throws HttpMalformedHeaderException {
        List<Integer> children = getChildLinks(pageNum);

        StringBuilder links = new StringBuilder();
        if (children.isEmpty()) {
            links.append("<li><a href=\"%s\">Home</a></li>\n".formatted(PREFIX));
        } else {
            for (int child : children) {
                links.append(
                        "<li><a href=\"%s\">Page %d</a></li>\n".formatted(pagePath(child), child));
            }
        }

        String body =
                """
                <!DOCTYPE html>
                <html>
                <head><title>Page %d</title></head>
                <body>
                <h1>Page %d</h1>
                <ul>
                %s</ul>
                </body>
                </html>
                """
                        .formatted(pageNum, pageNum, links);
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8, msg.getResponseBody().length()));
    }

    private List<Integer> getChildLinks(int pageNum) {
        List<Integer> links = new ArrayList<>();
        int firstChild = (pageNum + 1) * numLinks;
        for (int i = 0; i < numLinks; i++) {
            int child = firstChild + i;
            if (child < numPages) {
                links.add(child);
            }
        }
        return links;
    }

    private void send404(HttpMessage msg) throws HttpMalformedHeaderException {
        String body =
                """
                <!DOCTYPE html>
                <html>
                <body><h1>404 Not Found</h1></body>
                </html>
                """;
        msg.setResponseBody(body);
        msg.setResponseHeader(
                TestProxyServer.getDefaultResponseHeader(
                        TestProxyServer.STATUS_NOT_FOUND,
                        TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                        msg.getResponseBody().length()));
    }

    private String pagePath(int pageNum) {
        int depth = getDepth(numPages);
        String numStr = String.format("%0" + depth + "d", pageNum);
        StringBuilder path = new StringBuilder(PREFIX);
        for (char c : numStr.toCharArray()) {
            path.append('/').append(c);
        }
        return path.toString();
    }

    private static int getDepth(int n) {
        if (n <= 1) return 1;
        return String.valueOf(n - 1).length();
    }
}
