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
package org.zaproxy.addon.postman;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.zaproxy.addon.postman.models.Item;
import org.zaproxy.addon.postman.models.PostmanCollection;
import org.zaproxy.addon.postman.models.Request.Url;
import org.zaproxy.zap.testutils.TestUtils;

class ObjectDeserializerUnitTest extends TestUtils {

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
    }

    static Object[][] deserializationTestData() {
        return new Object[][] {
            {"{\"item\":{\"request\":{\"url\":{\"raw\":\"https://example.com\"}}}}"},
            {"{\"item\":{\"request\":{\"url\":\"https://example.com\"}}}"}
        };
    }

    @ParameterizedTest
    @MethodSource("deserializationTestData")
    void shouldDeserializeObject(String collectionJson) throws Exception {
        PostmanParser parser = new PostmanParser();
        PostmanCollection collection = parser.parse(collectionJson);

        Url url = ((Item) collection.getItem().get(0)).getRequest().getUrl();
        assertNotNull(url);

        String raw = url.getRaw();
        assertNotNull(raw);
        assertEquals(raw, "https://example.com");
    }

    @Test
    void shouldDeserializeInvalidObjectSilently() throws Exception {
        PostmanParser parser = new PostmanParser();
        String collectionJson = "{\"item\":{\"request\":{\"url\":true}}}}";

        PostmanCollection collection = assertDoesNotThrow(() -> parser.parse(collectionJson));
        assertNull(((Item) collection.getItem().get(0)).getRequest().getUrl());
    }
}
