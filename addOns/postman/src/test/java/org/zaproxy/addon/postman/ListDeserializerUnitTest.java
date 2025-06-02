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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.zaproxy.addon.postman.models.Item;
import org.zaproxy.addon.postman.models.ItemGroup;
import org.zaproxy.addon.postman.models.PostmanCollection;
import org.zaproxy.zap.testutils.TestUtils;

class ListDeserializerUnitTest extends TestUtils {

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
    }

    static Object[][] deserializationTestData() {
        return new Object[][] {
            {"{\"item\":{\"request\":{}}}", Item.class},
            {"{\"item\":{\"item\":[]}}", ItemGroup.class},
            {"{\"item\":[{\"request\":{}}]}", Item.class},
            {"{\"item\":[{\"item\":[{\"request\":{}}]}]}", ItemGroup.class}
        };
    }

    @ParameterizedTest
    @MethodSource("deserializationTestData")
    void shouldDeserializeItems(String collectionJson, Class<?> expectedType) throws Exception {
        PostmanParser parser = new PostmanParser();
        PostmanCollection collection = parser.parse(collectionJson);

        assertEquals(1, collection.getItem().size());
        assertTrue(expectedType.isInstance(collection.getItem().get(0)));
    }

    @Test
    void shouldParseWithInvalidItemsSilently() throws Exception {
        PostmanParser parser = new PostmanParser();
        String collectionJson = "{\"item\":[true,{\"randomKey\":\"randomValue\"}]}";

        PostmanCollection collection = assertDoesNotThrow(() -> parser.parse(collectionJson));
        assertEquals(1, collection.getItem().size());
        var item = collection.getItem().get(0);
        assertTrue(Item.class.isInstance(item));
        assertNull(((Item) item).getRequest());
    }
}
