/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;
import org.zaproxy.zap.extension.openapi.converter.swagger.RequestModelConverter;
import org.zaproxy.zap.testutils.TestUtils;

class PathGeneratorUnitTest extends TestUtils {
    Generators generators;

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
        generators = new Generators(null);
    }

    @Test
    void shouldUseExampleInQueryParameters() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/query-parameter-with-example",
                                        openAPI.getPaths()
                                                .get("/query-parameter-with-example")
                                                .getGet(),
                                        null),
                                generators)
                        .getUrl();

        assertEquals("/query-parameter-with-example?petId=42", request);
    }

    @Test
    void shouldUseExamplesInQueryParameters() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/query-parameter-with-examples",
                                        openAPI.getPaths()
                                                .get("/query-parameter-with-examples")
                                                .getGet(),
                                        null),
                                generators)
                        .getUrl();

        assertEquals("/query-parameter-with-examples?petId=42", request);
    }

    @Test
    void shouldUseSchemaExampleInQueryParameters() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/query-parameter-with-example-in-schema",
                                        openAPI.getPaths()
                                                .get("/query-parameter-with-example-in-schema")
                                                .getGet(),
                                        null),
                                generators)
                        .getUrl();

        assertEquals("/query-parameter-with-example-in-schema?petId=42", request);
    }

    private OpenAPI parseResource(String fileName) throws IOException {
        ParseOptions options = new ParseOptions();
        options.setResolveFully(true);
        String defn =
                IOUtils.toString(
                        this.getClass()
                                .getResourceAsStream(
                                        "/org/zaproxy/zap/extension/openapi/v3/" + fileName),
                        StandardCharsets.UTF_8);
        return new OpenAPIV3Parser().readContents(defn, new ArrayList<>(), options).getOpenAPI();
    }
}
