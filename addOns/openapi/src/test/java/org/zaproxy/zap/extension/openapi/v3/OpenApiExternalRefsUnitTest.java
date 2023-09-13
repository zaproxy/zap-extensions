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
package org.zaproxy.zap.extension.openapi.v3;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.testutils.HTTPDTestServer;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Test external references are accessed properly. */
class OpenApiExternalRefsUnitTest extends AbstractServerTest {

    private HTTPDTestServer externalServer;

    @BeforeEach
    void startExternalServer() throws IOException {
        externalServer = new HTTPDTestServer(0);
        externalServer.start();
    }

    @AfterEach
    void stopExternalServer() {
        if (externalServer != null) {
            externalServer.stop();
        }
    }

    @Test
    void shouldResolveExternalReferencesDirectly() throws Exception {
        // Given
        ServerHandler serverHandler = new ServerHandler();
        nano.addHandler(serverHandler);
        ServerHandler externalServerHandler = new ServerHandler();
        externalServer.addHandler(externalServerHandler);

        Converter converter =
                new SwaggerConverter(
                        getHtml(
                                "openapi_external_refs.yaml",
                                new String[][] {
                                    {"PORT", String.valueOf(nano.getListeningPort())},
                                    {"EXT_PORT", String.valueOf(externalServer.getListeningPort())}
                                }),
                        null);
        List<String> requestedUris = new ArrayList<>();
        RequesterListener listener =
                (message, initiator) ->
                        requestedUris.add(message.getRequestHeader().getURI().getEscapedPath());

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.addListener(listener);
        // When
        requestor.run(converter.getRequestModels());
        // Then
        assertThat(requestedUris, contains("/path/"));
        assertThat(serverHandler.getRequestedUris(), contains("/path/"));
        assertThat(externalServerHandler.getRequestedUris(), contains("/external/"));
    }

    private static class ServerHandler extends NanoServerHandler {

        private List<String> requestedUris;

        public ServerHandler() {
            super("");

            requestedUris = new ArrayList<>();
        }

        public List<String> getRequestedUris() {
            return requestedUris;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            requestedUris.add(session.getUri());

            consumeBody(session);
            return newFixedLengthResponse(Status.OK, NanoHTTPD.MIME_PLAINTEXT, "");
        }
    }
}
