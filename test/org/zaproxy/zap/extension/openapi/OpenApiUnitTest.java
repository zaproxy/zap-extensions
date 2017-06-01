/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.openapi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.URI;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.model.ValueGenerator;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public class OpenApiUnitTest extends ServerBasedTest {
    @Test
    public void shouldExplorePetStoreJson() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String response;
                String uri = session.getUri();
                if (uri.endsWith("defn.json")) {
                    response = getHtml("PetStore_defn.json");
                } else {
                    // We dont actually care about the response in this test ;)
                    response = getHtml("Blank.html");
                }
                return new Response(response);
            }
        });
        
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.json");
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequests(accessedUrls, "localhost:9090");
    }
    
    @Test
    public void shouldExplorePetStoreYaml() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreYaml/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String response;
                String uri = session.getUri();
                if (uri.endsWith("defn.yaml")) {
                    response = getHtml("PetStore_defn.yaml");
                } else {
                    // We dont actually care about the response in this test ;)
                    response = getHtml("Blank.html");
                }
                return new Response(response);
            }
        });
        
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.yaml");
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequests(accessedUrls, "localhost:9090");
    }
    
    @Test
    public void shouldExplorePetStoreJsonOverrideHost() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        String altHost = "localhost:8888";
        
        // Change port to check we use the new one
        this.nano.stop();
        nano = new HTTPDTestServer(8888);
        nano.start();

        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String response;
                String uri = session.getUri();
                if (uri.endsWith("defn.json")) {
                    response = getHtml("PetStore_defn.json");
                } else {
                    // We dont actually care about the response in this test ;)
                    response = getHtml("Blank.html");
                }
                return new Response(response);
            }
        });
        
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        requestor.setSiteOverride(altHost);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.json");
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequests(accessedUrls, altHost);
    }

    @Test
    public void shouldExplorePetStoreYamlLoop() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreYamlLoop/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String response;
                String uri = session.getUri();
                if (uri.endsWith("defn.yaml")) {
                    response = getHtml("PetStore_defn_loop.yaml");
                } else {
                    // We dont actually care about the response in this test ;)
                    response = getHtml("Blank.html");
                }
                return new Response(response);
            }
        });
        
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.yaml");
        SwaggerConverter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), null);
        requestor.run(converter.getRequestModels());
        
        List<String> errors = converter.getErrorMessages();

        assertTrue(errors.contains("Apparent loop in the OpenAPI definition:  / Category / Tag / Pet"));
    }
    
    @Test
    public void shouldUseValueGenerator() throws NullPointerException, IOException, SwaggerException {
        String test = "/PetStoreJson/";
        
        this.nano.addHandler(new NanoServerHandler(test) {
            @Override
            Response serve(IHTTPSession session) {
                String response;
                String uri = session.getUri();
                if (uri.endsWith("defn.json")) {
                    response = getHtml("PetStore_defn.json");
                } else {
                    // We dont actually care about the response in this test ;)
                    response = getHtml("Blank.html");
                }
                return new Response(response);
            }
        });
        
        Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
        HttpMessage defnMsg = this.getHttpMessage(test + "defn.json");
        
        ValueGenerator vg = new ValueGenerator(){
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
            }};
        
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()), vg);
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequestsValGen(accessedUrls, "localhost:9090");
    }

    private void checkPetStoreRequests(Map<String, String> accessedUrls, String host) {
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("POST http://" + host + "/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("PUT http://" + host + "/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/findByStatus?status=available"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/findByStatus?status=available"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("POST http://" + host + "/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet/10/uploadImage"));
        assertEquals("", accessedUrls.get("POST http://" + host + "/PetStore/pet/10/uploadImage"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/inventory"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/inventory"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/store/order"));
        assertEquals("{\"id\":10,\"petId\":10,\"quantity\":10,\"shipDate\":\"1970-01-01T00:00:00.001Z\",\"status\":\"placed\",\"complete\":true}",
                accessedUrls.get("POST http://" + host + "/PetStore/store/order"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user"));
        assertEquals("{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("POST http://" + host + "/PetStore/user"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithArray"));
        assertEquals("[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithArray"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithList"));
        assertEquals("[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithList"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/login?username=username&password=password"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/login?username=username&password=password"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/logout"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/logout"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/username"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/username"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/user/username"));
        assertEquals("{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("PUT http://" + host + "/PetStore/user/username"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/user/username"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/user/username"));
        // And that there arent any spurious ones
        assertEquals(20, accessedUrls.size());
        
    }

    private void checkPetStoreRequestsValGen(Map<String, String> accessedUrls, String host) {
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"Freda Smith\"},\"name\":\"Freda Smith\",\"photoUrls\":[\"http://www.example.com/fsmith.jpg\"],\"tags\":[{\"id\":10,\"name\":\"Freda Smith\"}],\"status\":\"unavailable\"}",
                accessedUrls.get("POST http://" + host + "/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"Freda Smith\"},\"name\":\"Freda Smith\",\"photoUrls\":[\"http://www.example.com/fsmith.jpg\"],\"tags\":[{\"id\":10,\"name\":\"Freda Smith\"}],\"status\":\"unavailable\"}",
                accessedUrls.get("PUT http://" + host + "/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/findByStatus?status=unavailable"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/findByStatus?status=unavailable"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/findByTags?tags=tags"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/pet/32"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet/32"));
        assertEquals("", accessedUrls.get("POST http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/pet/32"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/pet/32"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/pet/32/uploadImage"));
        assertEquals("", accessedUrls.get("POST http://" + host + "/PetStore/pet/32/uploadImage"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/inventory"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/inventory"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/store/order"));
        assertEquals("{\"id\":10,\"petId\":32,\"quantity\":10,\"shipDate\":\"1970-01-01T00:00:00.001Z\",\"status\":\"unavailable\",\"complete\":true}",
                accessedUrls.get("POST http://" + host + "/PetStore/store/order"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user"));
        assertEquals("{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}",
                accessedUrls.get("POST http://" + host + "/PetStore/user"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithArray"));
        assertEquals("[{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10},{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithArray"));
        assertTrue(accessedUrls.containsKey("POST http://" + host + "/PetStore/user/createWithList"));
        assertEquals("[{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10},{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}]",
                accessedUrls.get("POST http://" + host + "/PetStore/user/createWithList"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/login?username=fsmith&password=12345678"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/login?username=fsmith&password=12345678"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/logout"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/logout"));
        assertTrue(accessedUrls.containsKey("GET http://" + host + "/PetStore/user/fsmith"));
        assertEquals("", accessedUrls.get("GET http://" + host + "/PetStore/user/fsmith"));
        assertTrue(accessedUrls.containsKey("PUT http://" + host + "/PetStore/user/fsmith"));
        assertEquals("{\"id\":10,\"username\":\"fsmith\",\"firstName\":\"Freda\",\"lastName\":\"Smith\",\"email\":\"fsmith@example.com\",\"password\":\"12345678\",\"phone\":\"123 456 7890\",\"userStatus\":10}",
                accessedUrls.get("PUT http://" + host + "/PetStore/user/fsmith"));
        assertTrue(accessedUrls.containsKey("DELETE http://" + host + "/PetStore/user/fsmith"));
        assertEquals("", accessedUrls.get("DELETE http://" + host + "/PetStore/user/fsmith"));
        // And that there arent any spurious ones
        assertEquals(20, accessedUrls.size());
        
    }

}
