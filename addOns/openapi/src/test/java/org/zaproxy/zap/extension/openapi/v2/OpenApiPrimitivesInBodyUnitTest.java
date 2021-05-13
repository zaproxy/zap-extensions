/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.v2;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.testutils.NanoServerHandler;

class OpenApiPrimitivesInBodyUnitTest extends AbstractServerTest {

    @Test
    void shouldExploreBodiesWithPrimitiveValues()
            throws NullPointerException, IOException, SwaggerException {
        String test = "/OpenApi_defn_body_with_primitives/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String response;
                        String uri = session.getUri();
                        if (uri.endsWith("defn.json")) {
                            response =
                                    getHtml(
                                            "OpenApi_defn_body_with_primitives.json",
                                            new String[][] {
                                                {"PORT", String.valueOf(nano.getListeningPort())}
                                            });
                        } else {
                            // We dont actually care about the response in this test ;)
                            response = getHtml("Blank.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.json");
        Converter converter =
                new SwaggerConverter(
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        final Map<String, String> accessedUrls = new HashMap<>();
        RequesterListener listener =
                new RequesterListener() {
                    @Override
                    public void handleMessage(HttpMessage message, int initiator) {
                        accessedUrls.put(
                                message.getRequestHeader().getMethod()
                                        + " "
                                        + message.getRequestHeader().getURI().toString(),
                                message.getRequestBody().toString());
                    }
                };
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());

        checkRequests(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    private void checkRequests(Map<String, String> accessedUrls, String host) {
        // Check all of the expected URLs have been accessed and with the right data
        assertEquals("true", accessedUrls.get("POST http://" + host + "/api/boolean"));
        assertEquals("[true,true]", accessedUrls.get("POST http://" + host + "/api/booleans"));

        assertEquals("1.2", accessedUrls.get("POST http://" + host + "/api/double"));
        assertEquals("[1.2,1.2]", accessedUrls.get("POST http://" + host + "/api/doubles"));

        assertEquals("10", accessedUrls.get("POST http://" + host + "/api/integer"));
        assertEquals("[10,10]", accessedUrls.get("POST http://" + host + "/api/integers"));

        assertEquals("10", accessedUrls.get("POST http://" + host + "/api/long"));
        assertEquals("[10,10]", accessedUrls.get("POST http://" + host + "/api/longs"));

        assertEquals("\"John Doe\"", accessedUrls.get("POST http://" + host + "/api/string"));
        assertEquals(
                "[\"John Doe\",\"John Doe\"]",
                accessedUrls.get("POST http://" + host + "/api/strings"));

        assertEquals(10, accessedUrls.size());
    }
}
