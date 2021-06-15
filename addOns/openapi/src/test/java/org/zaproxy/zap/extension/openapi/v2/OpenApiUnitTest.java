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
package org.zaproxy.zap.extension.openapi.v2;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.AbstractServerTest;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.NanoServerHandler;

class OpenApiUnitTest extends AbstractServerTest {

    @Test
    void shouldExplorePetStoreJson() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        String defnName = "defn.json";

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        SwaggerConverter converter =
                new SwaggerConverter(
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        // No parsing errors
        assertThat(converter.getErrorMessages(), is(empty()));

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

        checkPetStoreRequests(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    @Test
    void shouldExplorePetStoreYaml() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreYaml/";
        String defnName = "defn.yaml";

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.yaml"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        SwaggerConverter converter =
                new SwaggerConverter(
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        // No parsing errors
        assertThat(converter.getErrorMessages(), is(empty()));

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

        checkPetStoreRequests(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    @Test
    void shouldExplorePetStoreOverridingHost()
            throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String altHost = "localhost:" + nano.getListeningPort();

        // Change port to check we use the new one
        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json", 9090));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        Converter converter =
                new SwaggerConverter(
                        altHost,
                        null,
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()),
                        null);
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

        checkPetStoreRequests(accessedUrls, altHost);
    }

    @Test
    void shouldExplorePetStoreWithDefaultHost()
            throws NullPointerException, IOException, SwaggerException {
        // Given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String defaultHost = "localhost:" + nano.getListeningPort();

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn_no_host.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        Converter converter =
                new SwaggerConverter(
                        null,
                        "http://" + defaultHost,
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()),
                        null);
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
        // When
        requestor.run(converter.getRequestModels());
        // Then
        checkPetStoreRequests(accessedUrls, defaultHost);
    }

    @Test
    void shouldFailToExplorePetStoreWithoutHost() throws Exception {
        // Given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String defaultHost = null;

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn_no_host.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        Converter converter =
                new SwaggerConverter(
                        null,
                        defaultHost,
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()),
                        null);
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
        // When / Then
        assertThrows(SwaggerException.class, () -> requestor.run(converter.getRequestModels()));
    }

    @Test
    void shouldExplorePetStoreWithDefaultScheme() throws Exception {
        // Given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String defaultScheme = "http://";

        this.nano.addHandler(
                new DefnServerHandler(test, defnName, "PetStore_defn_no_schemes.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.json");
        Converter converter =
                new SwaggerConverter(
                        null,
                        defaultScheme + "localhost:" + nano.getListeningPort(),
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()),
                        null);
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
        // When
        requestor.run(converter.getRequestModels());
        // Then
        checkPetStoreRequests(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    @Test
    void shouldFailToExplorePetStoreWithoutScheme() throws Exception {
        // Given
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        String defaultScheme = null;

        this.nano.addHandler(
                new DefnServerHandler(test, defnName, "PetStore_defn_no_schemes.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        Converter converter =
                new SwaggerConverter(
                        null,
                        defaultScheme,
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()),
                        null);
        // When / Then
        assertThrows(SwaggerException.class, () -> converter.getRequestModels());
    }

    @Test
    void shouldExplorePetStoreYamlLoop()
            throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreYamlLoop/";
        String defnName = "defn.yaml";
        String host = "localhost:" + nano.getListeningPort();

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn_loop.yaml"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        SwaggerConverter converter =
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
        // When
        requestor.run(converter.getRequestModels());
        // Then
        assertThat(converter.getErrorMessages(), is(empty()));
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\",\"x\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("POST http://" + host + "/PetStore/pet"));
    }

    @Test
    void shouldUseValueGenerator() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        String defnName = "defn.json";
        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn.json"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);

        ValueGenerator vg =
                new ValueGenerator() {
                    @Override
                    public String getValue(
                            URI uri,
                            String url,
                            String fieldId,
                            String defaultValue,
                            List<String> definedValues,
                            Map<String, String> envAttributes,
                            Map<String, String> fieldAttributes) {
                        if (fieldId.equals("status")) {
                            return "unavailable";
                        } else if (fieldId.equals("name")) {
                            return "Freda Smith";
                        } else if (fieldId.equals("firstName")) {
                            return "Freda";
                        } else if (fieldId.equals("lastName")) {
                            return "Smith";
                        } else if (fieldId.equals("username")) {
                            return "fsmith";
                        } else if (fieldId.equals("email")) {
                            return "fsmith@example.com";
                        } else if (fieldId.equals("photoUrls")) {
                            return "http://www.example.com/fsmith.jpg";
                        } else if (fieldId.equals("password")) {
                            return "12345678";
                        } else if (fieldId.equals("phone")) {
                            return "123 456 7890";
                        } else if (fieldId.equals("petId")) {
                            return "32";
                        }

                        return defaultValue;
                    }
                };

        Converter converter =
                new SwaggerConverter(
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), vg);
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

        checkPetStoreRequestsValGen(accessedUrls, "localhost:" + nano.getListeningPort());
    }

    @Test
    void shouldExplorePetStoreYamlWithExamples()
            throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreYamlExamples/";
        String defnName = "defn.yaml";

        this.nano.addHandler(new DefnServerHandler(test, defnName, "PetStore_defn_examples.yaml"));

        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + defnName);
        SwaggerConverter converter =
                new SwaggerConverter(
                        requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        // No parsing errors
        assertThat(converter.getErrorMessages(), is(empty()));

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

        assertEquals(accessedUrls.size(), 2);

        assertTrue(
                accessedUrls.containsKey(
                        "GET http://localhost:"
                                + nano.getListeningPort()
                                + "/PetStore/pet/findByStatus?status=available"));
        assertTrue(
                accessedUrls.containsKey(
                        "GET http://localhost:"
                                + nano.getListeningPort()
                                + "/PetStore/pet/42424242"));
    }

    private void checkPetStoreRequestsValGen(Map<String, String> accessedUrls, String host) {
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet"));
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"Freda Smith\"},\"name\":\"Freda Smith\",\"photoUrls\":[\"http://www.example.com/fsmith.jpg\"],\"tags\":[{\"id\":10,\"name\":\"Freda Smith\"}],\"status\":\"unavailable\"}",
                accessedUrls.get("POST http://" + host + "/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/pet"));
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"Freda Smith\"},\"name\":\"Freda Smith\",\"photoUrls\":[\"http://www.example.com/fsmith.jpg\"],\"tags\":[{\"id\":10,\"name\":\"Freda Smith\"}],\"status\":\"unavailable\"}",
                accessedUrls.get("PUT http://" + host + "/PetStore/pet"));
        assertTrue(
                accessedUrls.containsKey(
                        "GET http://" + host + "/PetStore/pet/findByStatus?status=unavailable"));
        assertEquals(
                "",
                accessedUrls.get(
                        "GET http://" + host + "/PetStore/pet/findByStatus?status=unavailable"));
        assertTrue(
                accessedUrls.containsKey(
                        "GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertEquals(
                "", accessedUrls.get("GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/32"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet/32"));
        assertEquals(
                "name=Freda+Smith&status=unavailable",
                accessedUrls.get("POST http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/pet/32"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/inventory"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/inventory"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/store/order"));
        assertEquals(
                "{\"id\":10,\"petId\":32,\"quantity\":10,\"shipDate\":\"1970-01-01T00:00:00.001Z\",\"status\":\"unavailable\",\"complete\":true}",
                accessedUrls.get("POST http://" + host + "/PetStore/store/order"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user"));
        assertEquals(
                "{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}",
                accessedUrls.get("POST http://" + host + "/PetStore/user"));
        assertTrue(
                accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithArray"));
        assertEquals(
                "[{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10},{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithArray"));
        assertTrue(
                accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithList"));
        assertEquals(
                "[{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10},{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithList"));
        assertTrue(
                accessedUrls.containsKey(
                        "GET http://"
                                + host
                                + "/PetStore/user/login?username=fsmith&password=12345678"));
        assertEquals(
                "",
                accessedUrls.get(
                        "GET http://"
                                + host
                                + "/PetStore/user/login?username=fsmith&password=12345678"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/logout"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/logout"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/fsmith"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/fsmith"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/user/fsmith"));
        assertEquals(
                "{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}",
                accessedUrls.get("PUT http://" + host + "/PetStore/user/fsmith"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/user/fsmith"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/user/fsmith"));
        // And that there arent any spurious ones
        assertEquals(19, accessedUrls.size());
    }

    private class DefnServerHandler extends NanoServerHandler {

        private final String defnName;
        private final String defnFileName;
        private final String port;

        public DefnServerHandler(String name, String defnName, String defnFileName) {
            this(name, defnName, defnFileName, nano.getListeningPort());
        }

        public DefnServerHandler(String name, String defnName, String defnFileName, int port) {
            super(name);
            this.defnName = defnName;
            this.defnFileName = defnFileName;
            this.port = String.valueOf(port);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String response;
            if (session.getUri().endsWith(defnName)) {
                response = getHtml(defnFileName, new String[][] {{"PORT", port}});
            } else {
                // We dont actually care about the response in this handler ;)
                response = getHtml("Blank.html");
            }
            return newFixedLengthResponse(response);
        }
    }
}
