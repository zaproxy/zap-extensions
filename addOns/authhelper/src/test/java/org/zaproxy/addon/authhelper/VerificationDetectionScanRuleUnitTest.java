/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Unit test for {@link VerificationDetectionScanRule}. */
class VerificationDetectionScanRuleUnitTest
        extends PassiveScannerTest<VerificationDetectionScanRule> {

    @Override
    protected VerificationDetectionScanRule createScanner() {
        return new VerificationDetectionScanRule();
    }

    @ParameterizedTest
    @ValueSource(strings = {"logout", "log-off", "sign-out", "sign-off", "end-session"})
    void shouldIgnoreSeemingLogoutUrls(String pathComponent) throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/%s HTTP/1.1".formatted(pathComponent));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"logout", "log-off", "sign-out", "sign-off"})
    void shouldIgnoreSeemingLogoutQueries(String queryComponent)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(
                "GET http://www.example.com/?action=%s HTTP/1.1".formatted(queryComponent));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Blah",
                "text/css",
                "text/javascript",
                "image/png",
                "image/svg+xml",
                "font/ttf"
            })
    void shouldIgnoreUnknownOrUnwantedContentTypes(String contentType)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/user/ HTTP/1.1");
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg.getRequestHeader().setHeader(HttpHeader.REFERER, "http://www.example.com/");
        msg.setResponseBody("<html>User: jsmith</html>");
        msg.setResponseHeader(
                """
                HTTP/1.1 200 OK\r
                Server: Apache-Coyote/1.1\r
                Content-Type: text/html;charset=ISO-8859-1\r
                Content-Length: %s\r\n\r
                """
                        .formatted(msg.getResponseBody().length()));
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }
}
