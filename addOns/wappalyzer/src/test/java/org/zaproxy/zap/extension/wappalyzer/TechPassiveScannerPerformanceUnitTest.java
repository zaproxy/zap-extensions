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
package org.zaproxy.zap.extension.wappalyzer;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

/**
 * Guards against the passive scan rule taking minutes on large responses.
 *
 * <p>The cost scales with the number of technologies, so these tests scan against all of the
 * bundled technologies. The inputs are generated, and each limit is a few times the time taken
 * after the fix, while the old behaviour is slower than it.
 *
 * <p>Scan times (QUICK mode, one run each, bundled technologies at the time of writing) before and
 * after the fix:
 *
 * <table>
 * <caption>Scan times</caption>
 * <tr><th>Input</th><th>Before</th><th>After</th></tr>
 * <tr><td>HTML, 25 KB</td><td>14.4 s</td><td>0.8 s</td></tr>
 * <tr><td>JavaScript, 3 MB</td><td>more than 60 s (timed out)</td><td>0.3 s</td></tr>
 * <tr><td>JSON, 3 MB</td><td>more than 60 s (timed out)</td><td>0.05 s</td></tr>
 * <tr><td>HTML, 50 KB of {@code a<b } (Vue.js pattern)</td><td>more than 60 s (timed out)</td><td>1.8 s</td></tr>
 * </table>
 */
class TechPassiveScannerPerformanceUnitTest extends PassiveScannerTestUtils<TechPassiveScanner> {

    private static List<Application> apps;

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWappalyzer());
    }

    @Override
    protected TechPassiveScanner createScanner() {
        ApplicationHolder holder = mock(ApplicationHolder.class);
        lenient().when(holder.getApplications()).thenReturn(getApps());
        lenient().doNothing().when(holder).addApplicationsToSite(anyString(), any());
        return new TechPassiveScanner(holder);
    }

    private static synchronized List<Application> getApps() {
        if (apps == null) {
            List<String> files = new ArrayList<>();
            for (char c : "_abcdefghijklmnopqrstuvwxyz".toCharArray()) {
                files.add(ExtensionWappalyzer.RESOURCE + "/technologies/" + c + ".json");
            }
            apps =
                    new ArrayList<>(
                            new TechsJsonParser()
                                    .parse(
                                            ExtensionWappalyzer.RESOURCE + "/categories.json",
                                            files,
                                            false)
                                    .getApplications());
        }
        return apps;
    }

    @Test
    void shouldScanLargeHtmlResponseInReasonableTime() throws HttpMalformedHeaderException {
        // Given
        String chunk =
                """
                <div class="row item"><a href="/products/item" data-id="42">Item</a>\
                <img src="/img/a.png" alt="a"><script src="/js/chunk.js"></script>\
                <link rel="stylesheet" href="/css/site.css"><meta name="x" content="y">\
                <style>.item { color: red; }</style><p>Some text &amp; more text.</p></div>
                """;
        HttpMessage msg = message("text/html", "<html><head></head><body>\n", chunk, 25_000);
        // When / Then
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldScanLargeJavaScriptResponseInReasonableTime() throws HttpMalformedHeaderException {
        // Given
        String chunk =
                "var h = '<div class=\"row\"><a href=\"/x\" data-id=\"1\">x</a></div>';"
                        + " el.innerHTML = h; function f(a, b) { return a < b ? a : b; }\n";
        HttpMessage msg = message("application/javascript", "", chunk, 3_000_000);
        // When / Then
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldScanLargeJsonResponseInReasonableTime() throws HttpMalformedHeaderException {
        // Given
        String chunk =
                "{\"html\":\"<div class=\\\"row\\\"><a href=\\\"/x\\\">x</a></div>\",\"n\":1},";
        HttpMessage msg = message("application/json", "[", chunk, 3_000_000);
        // When / Then
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldScanLargeHtmlResponseWithManyOpeningAnglesInReasonableTime()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = message("text/html", "<html><body>", "a<b ", 50_000);
        // When / Then
        assertTimeoutPreemptively(Duration.ofSeconds(6), () -> scanHttpResponseReceive(msg));
    }

    private static HttpMessage message(String contentType, String intro, String chunk, int size)
            throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.setResponseBody(intro + chunk.repeat(size / chunk.length() + 1));
        return msg;
    }
}
