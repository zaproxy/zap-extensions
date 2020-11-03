/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.StaticContentServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

public class GraphQlParserUnitTest extends TestUtils {

    String endpointUrl;

    @BeforeEach
    public void setup() throws Exception {
        setUpZap();
        startServer();
        endpointUrl = "http://localhost:" + nano.getListeningPort();
    }

    @AfterEach
    public void teardown() throws Exception {
        stopServer();
    }

    @Test
    public void shouldFailIntrospectionWhenResponseIsEmpty() throws Exception {
        nano.addHandler(new StaticContentServerHandler("/", ""));
        assertThrows(IOException.class, () -> new GraphQlParser(endpointUrl).introspect());
    }

    @Test
    public void shouldFailIntrospectionWhenResponseIsNotJson() throws Exception {
        nano.addHandler(new StaticContentServerHandler("/", "not json"));
        assertThrows(IOException.class, () -> new GraphQlParser(endpointUrl).introspect());
    }
}
