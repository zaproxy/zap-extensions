/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.v1;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
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

class OpenApiUnitTest extends AbstractServerTest {

    @Test
    void shouldExplorePetStore1_2() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStore_1_2_defn/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String response;
                        String uri = session.getUri();
                        if (uri.endsWith("defn.json")) {
                            response =
                                    getHtml(
                                            "PetStore_defn.json",
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

        checkPetStore2dot0Requests(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    private void checkPetStore2dot0Requests(Map<String, String> accessedUrls, String host) {
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/store/order"));
        assertEquals(
                "{\"id\":10,\"petId\":10,\"quantity\":10,\"status\":\"placed\",\"shipDate\":\"1970-01-01T00:00:00.001Z\"}",
                accessedUrls.get("POST http://" + host + "/store/order"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/store/order/orderId"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/store/order/orderId"));
        assertEquals(3, accessedUrls.size());
    }
}
