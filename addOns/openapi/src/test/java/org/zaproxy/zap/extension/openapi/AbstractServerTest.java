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
package org.zaproxy.zap.extension.openapi;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

/**
 * Base class for OpenAPI tests that require a server.
 *
 * <p>It's responsible for {@link #startServer() starting} and {@link #stopServer() stopping} the
 * HTTP test server for each test method.
 */
public abstract class AbstractServerTest extends AbstractOpenApiTest {

    @BeforeEach
    void init() throws Exception {
        startServer();
    }

    @AfterEach
    void teardown() {
        stopServer();
    }

    protected static void checkPetStoreRequests(Map<String, String> accessedUrls, String host) {
        checkPetStoreRequests(accessedUrls, "http", host);
    }

    protected static void checkPetStoreRequests(
            Map<String, String> accessedUrls, String scheme, String host) {
        checkPetStoreRequests(accessedUrls, scheme, host, "/PetStore");
    }

    protected static void checkPetStoreRequests(
            Map<String, String> accessedUrls, String scheme, String host, String path) {
        String baseUrl = scheme + "://" + host + path;
        // Check all of the expected URLs have been accessed and with the right data
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/pet"));
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("POST " + baseUrl + "/pet"));
        assertTrue(accessedUrls.containsKey("PUT " + baseUrl + "/pet"));
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                accessedUrls.get("PUT " + baseUrl + "/pet"));
        assertTrue(
                accessedUrls.containsKey("GET " + baseUrl + "/pet/findByStatus?status=available"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/pet/findByStatus?status=available"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/pet/findByTags?tags=tags"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/pet/findByTags?tags=tags"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/pet/10"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/pet/10"));
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/pet/10"));
        assertEquals("name=name&status=status", accessedUrls.get("POST " + baseUrl + "/pet/10"));
        assertTrue(accessedUrls.containsKey("DELETE " + baseUrl + "/pet/10"));
        assertEquals("", accessedUrls.get("DELETE " + baseUrl + "/pet/10"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/store/inventory"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/store/inventory"));
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/store/order"));
        assertEquals(
                "{\"id\":10,\"petId\":10,\"quantity\":10,\"shipDate\":\"1970-01-01T00:00:00.001Z\",\"status\":\"placed\",\"complete\":true}",
                accessedUrls.get("POST " + baseUrl + "/store/order"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/store/order/10"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/store/order/10"));
        assertTrue(accessedUrls.containsKey("DELETE " + baseUrl + "/store/order/10"));
        assertEquals("", accessedUrls.get("DELETE " + baseUrl + "/store/order/10"));
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/user"));
        assertEquals(
                "{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("POST " + baseUrl + "/user"));
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/user/createWithArray"));
        assertEquals(
                "[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST " + baseUrl + "/user/createWithArray"));
        assertTrue(accessedUrls.containsKey("POST " + baseUrl + "/user/createWithList"));
        assertEquals(
                "[{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10},{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}]",
                accessedUrls.get("POST " + baseUrl + "/user/createWithList"));
        assertTrue(
                accessedUrls.containsKey(
                        "GET " + baseUrl + "/user/login?username=username&password=password"));
        assertEquals(
                "",
                accessedUrls.get(
                        "GET " + baseUrl + "/user/login?username=username&password=password"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/user/logout"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/user/logout"));
        assertTrue(accessedUrls.containsKey("GET " + baseUrl + "/user/username"));
        assertEquals("", accessedUrls.get("GET " + baseUrl + "/user/username"));
        assertTrue(accessedUrls.containsKey("PUT " + baseUrl + "/user/username"));
        assertEquals(
                "{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\",\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}",
                accessedUrls.get("PUT " + baseUrl + "/user/username"));
        assertTrue(accessedUrls.containsKey("DELETE " + baseUrl + "/user/username"));
        assertEquals("", accessedUrls.get("DELETE " + baseUrl + "/user/username"));
        // And that there arent any spurious ones
        assertEquals(19, accessedUrls.size());
    }
}
