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
import java.util.Map;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException;
import org.zaproxy.zap.extension.openapi.network.RequesterListener;
import org.zaproxy.zap.extension.openapi.network.Requestor;

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
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()));
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequests(accessedUrls);
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
        Converter converter = new SwaggerConverter(requestor.getResponseBody(defnMsg.getRequestHeader().getURI()));
        final Map<String, String> accessedUrls = new HashMap<String, String>();
        RequesterListener listener = new RequesterListener(){
            @Override
            public void handleMessage(HttpMessage message, int initiator) {
                accessedUrls.put(message.getRequestHeader().getMethod() + " " + 
                        message.getRequestHeader().getURI().toString(), message.getRequestBody().toString());
                
            }};
        requestor.addListener(listener);
        requestor.run(converter.getRequestModels());
        
        checkPetStoreRequests(accessedUrls);
    }
    
    private void checkPetStoreRequests(Map<String, String> accessedUrls) {
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("POST http://localhost:9090/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("PUT http://localhost:9090/PetStore/pet"));
        assertEquals("{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("PUT http://localhost:9090/PetStore/pet"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/pet/findByStatus?status=available"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/pet/findByStatus?status=available"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/pet/findByTags?tags=Test"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/pet/findByTags?tags=Test"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("POST http://localhost:9090/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://localhost:9090/PetStore/pet/10"));
        assertEquals("", accessedUrls.get("DELETE http://localhost:9090/PetStore/pet/10"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/pet/10/uploadImage"));
        assertEquals("", accessedUrls.get("POST http://localhost:9090/PetStore/pet/10/uploadImage"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/store/inventory"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/store/inventory"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/store/order"));
        assertEquals("{\"id\":10,\"petId\":10,\"quantity\":10,\"shipDate\":\"1970-01-01T00:00:00.001Z\",\"status\":\"placed\",\"complete\":true}",
                accessedUrls.get("POST http://localhost:9090/PetStore/store/order"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("DELETE http://localhost:9090/PetStore/store/order/10"));
        assertEquals("", accessedUrls.get("DELETE http://localhost:9090/PetStore/store/order/10"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/user"));
        assertEquals("{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("POST http://localhost:9090/PetStore/user"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/user/createWithArray"));
        assertEquals("[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST http://localhost:9090/PetStore/user/createWithArray"));
        assertTrue(accessedUrls.containsKey("POST http://localhost:9090/PetStore/user/createWithList"));
        assertEquals("[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST http://localhost:9090/PetStore/user/createWithList"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/user/login?username=username&password=password"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/user/login?username=username&password=password"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/user/logout"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/user/logout"));
        assertTrue(accessedUrls.containsKey("GET http://localhost:9090/PetStore/user/username"));
        assertEquals("", accessedUrls.get("GET http://localhost:9090/PetStore/user/username"));
        assertTrue(accessedUrls.containsKey("PUT http://localhost:9090/PetStore/user/username"));
        assertEquals("{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("PUT http://localhost:9090/PetStore/user/username"));
        assertTrue(accessedUrls.containsKey("DELETE http://localhost:9090/PetStore/user/username"));
        assertEquals("", accessedUrls.get("DELETE http://localhost:9090/PetStore/user/username"));
        // And that there arent any spurious ones
        assertEquals(20, accessedUrls.size());
        
    }
}
