/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;
import org.zaproxy.zap.extension.openapi.converter.swagger.RequestModelConverter;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.testutils.TestUtils;

class OpenApiIntegrationXmlTest extends TestUtils {

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionOpenApi());
        Constant.messages = null; // leave default initialized by TestUtils/mockMessages
    }

    @Test
    void shouldGenerateXmlRequestBodiesAndNoUnsupportedMessage() throws Exception {
        String defn =
                IOUtils.toString(
                        this.getClass()
                                .getResourceAsStream(
                                        "/org/zaproxy/zap/extension/openapi/v3/openapi_xml_integration.yaml"),
                        StandardCharsets.UTF_8);

        ParseOptions options = new ParseOptions();
        options.setResolveFully(true);
        OpenAPI openAPI =
                new OpenAPIV3Parser().readContents(defn, new ArrayList<>(), options).getOpenAPI();

        Generators generators = new Generators(null);
        OperationModel operationModel =
                new OperationModel("/xml", openAPI.getPaths().get("/xml").getPost(), null);

        RequestModelConverter converter = new RequestModelConverter();
        String body = converter.convert(operationModel, generators).getBody();

        // Body should be non-empty and should look like XML
        org.junit.jupiter.api.Assertions.assertNotNull(body);
        org.junit.jupiter.api.Assertions.assertFalse(body.isEmpty());
        // Quick sanity parse
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        db.parse(new java.io.ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        // There should be no unsupported-content error message for application/xml
        assertThat(
                generators.getErrorMessages().stream()
                        .filter(
                                s ->
                                        s.contains(
                                                "the content type application/xml is not supported"))
                        .toList(),
                empty());

        // The overall error messages list may be empty; we've already asserted the
        // specific
        // unsupported-content message is not present above.
    }
}
