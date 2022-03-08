/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.generators;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link DataGenerator}. */
class DataGeneratorUnitTest extends TestUtils {

    private DataGenerator generator;

    @BeforeAll
    static void setUp() {
        mockMessages(new ExtensionOpenApi());
    }

    @AfterAll
    static void cleanUp() {
        Constant.messages = null;
    }

    @BeforeEach
    void init() {
        Generators generators = new Generators(null);
        generator = generators.getDataGenerator();
    }

    @Test
    void shouldUseContentInParameter() throws IOException {
        // Given
        OpenAPI openAPI = parseResource("defn-with-query-params.yml");
        Parameter parameter =
                openAPI.getPaths().get("/content-json").getGet().getParameters().get(0);
        // When
        String data = generator.generate(parameter.getName(), parameter);
        // Then
        assertEquals("{\"id\":10,\"name\":\"John Doe\"}", data);
    }

    private OpenAPI parseResource(String fileName) throws IOException {
        ParseOptions options = new ParseOptions();
        options.setResolveFully(true);
        String defn =
                IOUtils.toString(
                        this.getClass().getResourceAsStream(fileName), StandardCharsets.UTF_8);
        return new OpenAPIV3Parser().readContents(defn, new ArrayList<>(), options).getOpenAPI();
    }
}
