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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;

public class PostmanParserUnitTest extends TestUtils {

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
    }

    @AfterEach
    void teardown() throws Exception {
        stopServer();
    }

    @Test
    void shouldFailWhenDefnIsInvalidJson() throws Exception {
        PostmanParser parser = new PostmanParser();
        assertThrows(IOException.class, () -> parser.importDefinition("{"));
    }

    @Test
    void shouldParseWhenDefnIsValidJson() throws Exception {
        PostmanParser parser = new PostmanParser();
        assertDoesNotThrow(() -> parser.parse("{}"));
    }

    @Test
    void shouldParseKnownAttributes() throws Exception {
        PostmanParser parser = new PostmanParser();
        String defn = "{\"item\":true,\"variable\":\"\"}"; // Random types for leniency
        PostmanCollection collection = parser.parse(defn);

        assertNotNull(collection.getItem());
        assertNotNull(collection.getVariable());
    }

    @Test
    void shouldIgnoreUnKnownAttributes() throws Exception {
        PostmanParser parser = new PostmanParser();
        String defn = "{\"unKnown1\":true,\"unKnown2\":\"\"}";
        assertDoesNotThrow(() -> parser.parse(defn));
    }
}
