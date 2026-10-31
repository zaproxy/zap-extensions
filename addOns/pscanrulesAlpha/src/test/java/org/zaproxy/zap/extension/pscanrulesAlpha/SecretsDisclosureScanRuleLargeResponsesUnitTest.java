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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import java.time.Duration;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Guards against the passive scan rule taking very long on large responses.
 *
 * <p>The inputs are generated (an intro, a chunk repeated up to the size, and an outro with a
 * secret) and each limit is many times the time taken at the time of writing, as CI machines are
 * much slower, they are to catch much slower scans. The scans are not stopped when they exceed the
 * limit, a scan can't be interrupted and would keep using the CPU for the other tests, instead the
 * failure says by how much the limit was exceeded. The chunks have the words (the Gitleaks
 * keywords) that matter, as most of the rules start with a prefix that can match anywhere in the
 * content, which is slow, so the rules are only run on the windows around their keywords.
 *
 * <p>Scan times (MEDIUM threshold unless noted, one run each, including building the body, at the
 * time of writing), and the limits:
 *
 * <table>
 * <caption>Scan times</caption>
 * <tr><th>Input</th><th>Time</th><th>Limit</th></tr>
 * <tr><td>JSON, 2 MB</td><td>1.5 s</td><td>15 s</td></tr>
 * <tr><td>Minified JavaScript (one line), 2 MB</td><td>1.5 s</td><td>15 s</td></tr>
 * <tr><td>HTML, 2 MB</td><td>1.6 s</td><td>15 s</td></tr>
 * <tr><td>{@code twitter key } repeated, 0.5 MB</td><td>0.7 s</td><td>12 s</td></tr>
 * <tr><td>JWT header repeated without separators, 2 MB</td><td>0.2 s</td><td>5 s</td></tr>
 * <tr><td>{@code secret = 'Password7qZ8vN2r'; } repeated on a single line, LOW threshold, 1
 * MB</td><td>2.9 s</td><td>25 s</td></tr>
 * </table>
 *
 * <p>On real files (a 15.8 MB HTML page, a 9 MB JS file and a 26 MB JSON file) the scan took 38 s,
 * 11 s and about 17 s before the scan was limited to the windows, and 4.1 s, 1.7 s and 7.5 s after.
 */
class SecretsDisclosureScanRuleLargeResponsesUnitTest
        extends PassiveScannerTest<SecretsDisclosureScanRule> {

    private static final String AWS_KEY = "AKIAQYLPMN5HFIQR7XYZ";

    @Override
    protected SecretsDisclosureScanRule createScanner() {
        return new SecretsDisclosureScanRule();
    }

    static Stream<Arguments> largeResponses() {
        return Stream.of(
                Arguments.of(
                        "JSON",
                        "application/json",
                        "[",
                        "{\"id\":1,\"name\":\"item\",\"token\":\"x\",\"text\":\"The api key for twitter and"
                                + " yandex, they said\",\"values\":[1,2,3],\"url\":\"https://example.com/a?b=c\"},",
                        2_000_000,
                        "{\"k\":\"" + AWS_KEY + "\"}]",
                        15),
                Arguments.of(
                        "minified JavaScript, a single line",
                        "application/javascript",
                        "",
                        "function f(a,b){return a<b?a:b}var token=a.api||\"x\";"
                                + "el.innerHTML='<div class=\"row\">twitter yandex</div>';",
                        2_000_000,
                        ";var k=\"" + AWS_KEY + "\";",
                        15),
                Arguments.of(
                        "HTML",
                        "text/html",
                        "<html><body>\n",
                        """
                        <div class="row item"><a href="/products/item" data-id="42">Item</a>\
                        <script src="/js/chunk.js"></script><link rel="stylesheet" href="/css/site.css">\
                        <p>They always key in the survey, see twitter and yandex &amp; more.</p></div>
                        """,
                        2_000_000,
                        "<p>" + AWS_KEY + "</p></body></html>",
                        15),
                // The windows around the keywords all merge.
                Arguments.of(
                        "a keyword every few characters",
                        "text/plain",
                        "",
                        "twitter key ",
                        500_000,
                        "\n" + AWS_KEY + "\n",
                        12),
                // No separators, for the regexes with unbounded runs (e.g. a JWT).
                Arguments.of(
                        "long runs of characters",
                        "text/plain",
                        "",
                        "eyJhbGciOiJIUzI1NiJ9",
                        2_000_000,
                        "\n" + AWS_KEY + "\n",
                        5));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("largeResponses")
    void shouldScanLargeResponseInReasonableTime(
            String description,
            String contentType,
            String intro,
            String chunk,
            int size,
            String outro,
            int maxSeconds)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = message(contentType, intro, chunk, size, outro);
        // When
        assertTimeout(Duration.ofSeconds(maxSeconds), () -> scanHttpResponseReceive(msg));
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), containsString(AWS_KEY));
    }

    @Test
    void shouldScanLargeSingleLineResponseWithManyAllowedCandidatesInReasonableTime()
            throws HttpMalformedHeaderException {
        // Given: at Low threshold, the generic rule has many candidates on the same huge line.
        HttpMessage msg = message("text/plain", "", "secret = 'Password7qZ8vN2r'; ", 1_000_000, "");
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When / Then
        assertTimeout(Duration.ofSeconds(25), () -> scanHttpResponseReceive(msg));
        assertThat(alertsRaised, hasSize(0));
    }

    private static HttpMessage message(
            String contentType, String intro, String chunk, int size, String outro)
            throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/ HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n");
        msg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.setResponseBody(intro + chunk.repeat(size / chunk.length() + 1) + outro);
        return msg;
    }
}
