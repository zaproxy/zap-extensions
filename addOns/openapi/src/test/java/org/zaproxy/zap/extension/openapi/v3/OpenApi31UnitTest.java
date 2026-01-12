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
package org.zaproxy.zap.extension.openapi.v3;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Test OpenAPI 3.1 specific features. */
class OpenApi31UnitTest extends AbstractServerTest {

    @Test
    void shouldParseOpenApi31TypeArrays() throws Exception {
        // Given
        this.nano.addHandler(new PlainResponseServerHandler());
        int port = nano.getListeningPort();

        SwaggerConverter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_31_type_arrays.yaml",
                                new String[][] {{"PORT", String.valueOf(nano.getListeningPort())}}),
                        null);
        // Then - should parse without errors
        assertThat(converter.getErrorMessages(), is(empty()));

        List<HttpMessage> accessedMessages = new ArrayList<>();
        RequesterListener listener = (message, initiator) -> accessedMessages.add(message);

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels(null));
        // Then - should generate requests
        assertThat(accessedMessages.size(), is(3));
        assertThat(
                accessedMessages.get(0).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/parameters/path/Name/"));
        assertThat(
                accessedMessages.get(1).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/parameters/query?Name=Name"));
        assertThat(
                accessedMessages.get(2).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/body/json/nullable"));
        assertThat(
                accessedMessages.get(2).getRequestBody().toString(),
                is("{\"NameA\":\"John Doe\",\"NameB\":10,\"NameC\":true}"));
    }

    @Test
    void shouldParseOpenApi31ExclusiveMinMax() throws Exception {
        // Given
        this.nano.addHandler(new PlainResponseServerHandler());
        int port = nano.getListeningPort();

        SwaggerConverter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_31_exclusive_minmax.yaml",
                                new String[][] {{"PORT", String.valueOf(nano.getListeningPort())}}),
                        null);
        // Then - should parse without errors
        assertThat(converter.getErrorMessages(), is(empty()));

        List<HttpMessage> accessedMessages = new ArrayList<>();
        RequesterListener listener = (message, initiator) -> accessedMessages.add(message);

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels(null));
        // Then - should generate requests
        assertThat(accessedMessages.size(), is(2));
        assertThat(
                accessedMessages.get(0).getRequestHeader().getURI().toString(),
                is(
                        "http://localhost:"
                                + port
                                + "/parameters/query/exclusive?minValue=10&maxValue=10&minMaxValue=1.2"));
        assertThat(
                accessedMessages.get(1).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/body/json/exclusive"));
        assertThat(
                accessedMessages.get(1).getRequestBody().toString(),
                is("{\"minValue\":10,\"maxValue\":10,\"minMaxValue\":1.2}"));
    }

    @Test
    void shouldParseOpenApi31ExamplesArray() throws Exception {
        // Given
        this.nano.addHandler(new PlainResponseServerHandler());
        int port = nano.getListeningPort();

        SwaggerConverter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_31_examples_array.yaml",
                                new String[][] {{"PORT", String.valueOf(nano.getListeningPort())}}),
                        null);
        // Then - should parse without errors
        assertThat(converter.getErrorMessages(), is(empty()));

        List<HttpMessage> accessedMessages = new ArrayList<>();
        RequesterListener listener = (message, initiator) -> accessedMessages.add(message);

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels(null));
        // Then - should generate requests
        assertThat(accessedMessages.size(), is(3));
        assertThat(
                accessedMessages.get(0).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/parameters/query/examples?Name=value1"));
        assertThat(
                accessedMessages.get(1).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/body/json/examples"));
        assertThat(
                accessedMessages.get(1).getRequestBody().toString(), is("{\"Name\":\"example1\"}"));
        assertThat(
                accessedMessages.get(2).getRequestHeader().getURI().toString(),
                is("http://localhost:" + port + "/responses/examples"));
    }

    private static class PlainResponseServerHandler extends NanoServerHandler {

        public PlainResponseServerHandler() {
            super("");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            consumeBody(session);
            return newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_PLAINTEXT, "");
        }
    }
}
