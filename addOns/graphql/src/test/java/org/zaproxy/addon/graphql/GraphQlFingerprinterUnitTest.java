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
package org.zaproxy.addon.graphql;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

public class GraphQlFingerprinterUnitTest extends TestUtils {

    String endpointUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        endpointUrl = "http://localhost:" + nano.getListeningPort() + "/graphql";
    }

    @AfterEach
    void teardown() {
        stopServer();
    }

    @Test
    void shouldFindSubstringInErrorResponse() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/graphql") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                NanoHTTPD.Response.Status.OK,
                                "application/json",
                                "{\"errors\": [{\"code\":\"Oh no! Something went wrong.\"}]}");
                    }
                });
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{zaproxy}");
        // Then
        assertThat(fp.errorContains("Something", "code"), is(true));
    }

    @Test
    void shouldNotSendTheSameQueryMultipleTimes() throws Exception {
        // Given
        var handler =
                new NanoServerHandler("/graphql") {
                    private int requestCount = 0;

                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        consumeBody(session);
                        return newFixedLengthResponse(
                                NanoHTTPD.Response.Status.OK,
                                "application/json",
                                "{\"data\": {\"count\": " + ++requestCount + "}}");
                    }

                    int getRequestCount() {
                        return requestCount;
                    }
                };
        nano.addHandler(handler);
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{count}");
        fp.sendQuery("{count}");
        fp.sendQuery("{count}");
        // Then
        assertThat(handler.getRequestCount(), is(equalTo(1)));
    }

    @Test
    void shouldSendQuery() throws Exception {
        // Given
        nano.addHandler(
                new StaticContentServerHandler(
                        "/graphql", "{\"data\": {\"__typename\": \"Query\"}}"));
        var fp = new GraphQlFingerprinter(UrlBuilder.build(endpointUrl));
        // When
        fp.sendQuery("{__typename}");
        // Then
        assertThat(nano.getRequestedUris(), hasSize(1));
    }
}
