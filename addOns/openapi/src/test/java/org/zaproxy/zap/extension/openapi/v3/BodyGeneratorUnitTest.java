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
package org.zaproxy.zap.extension.openapi.v3;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
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
import org.zaproxy.zap.extension.openapi.generators.BodyGenerator;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.testutils.TestUtils;

class BodyGeneratorUnitTest extends TestUtils {
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
    void shouldGenerateArrayOfStrings() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");
        String jsonArray =
                generators
                        .getBodyGenerator()
                        .generate(
                                openAPI.getPaths()
                                        .get("/pet/findByTags")
                                        .getGet()
                                        .getParameters()
                                        .get(0)
                                        .getSchema());
        assertEquals("[\"John Doe\",\"John Doe\"]", jsonArray);
    }

    @Test
    void shouldGenerateArrayOfEnums() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");
        String jsonArray =
                generators
                        .getBodyGenerator()
                        .generate(
                                openAPI.getPaths()
                                        .get("/pet/findByStatus")
                                        .getGet()
                                        .getParameters()
                                        .get(0)
                                        .getSchema());
        assertEquals("[\"available\",\"available\"]", jsonArray);
    }

    @Test
    void shouldGenerateJsonObject() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");

        String jsonString =
                generators
                        .getBodyGenerator()
                        .generate(openAPI.getComponents().getSchemas().get("User"));
        String output =
                "{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\","
                        + "\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}";
        assertEquals(output, jsonString);
    }

    @Test
    void shouldGenerateFileContents() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String fileContents =
                generators
                        .getBodyGenerator()
                        .generate(
                                ((Schema<?>)
                                                openAPI.getPaths()
                                                        .get("/v3/openapi/multipartBinary")
                                                        .getPost()
                                                        .getRequestBody()
                                                        .getContent()
                                                        .get("multipart/form-data")
                                                        .getSchema())
                                        .getProperties()
                                        .get("file"));
        String output = BodyGenerator.TEXT_FILE_CONTENTS;
        assertEquals(output, fileContents);
    }

    @Test
    void objectSchemaWithoutProperties() throws IOException {
        OpenAPI openAPI = parseResource("Object_schema_without_properties.json");

        String jsonString =
                generators
                        .getBodyGenerator()
                        .generate(openAPI.getComponents().getSchemas().get("credentials"));
        String output = "{\"userName\":\"John Doe\",\"password\":\"John Doe\"}";
        assertEquals(output, jsonString);
    }

    @Test
    void shouldHandleRequestBodyRef() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        null, openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                requestBody);
    }

    @Test
    void shouldGenerateFormData() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pet/{petId}",
                                        openAPI.getPaths().get("/pet/{petId}").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals("name=name&status=status", requestBody);
    }

    @Test
    void complexObjectInFormData() throws IOException {
        OpenAPI openAPI = parseResource("Complex_object_in_form_data.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pet", openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        assertEquals(
                "p1=p1&p2=%7B%22id%22%3A10%2C%22category%22%3A%7B%22id%22%3A10%2C%22name%22%3A%22John+Doe%22%7D%2C%22name%22%3A%22John+Doe%22%2C%22photoUrls%22%3A%5B%22John+Doe%22%5D%2C%22tags%22%3A%5B%7B%22id%22%3A10%2C%22name%22%3A%22John+Doe%22%7D%5D%7D",
                requestBody);
    }

    @Test
    void arrayInFormData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_with_array_in_form.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pet", openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        assertEquals("somearray=%5B1.2%2C1.2%5D", requestBody);
    }

    @Test
    void shouldGenerateMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/multipartMultiple",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/multipartMultiple")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        String boundary = requestBody.substring(0, 38);

        assertEquals(
                boundary
                        + "\r\n"
                        + "Content-Disposition: form-data; name=\"additionalMetadata\"\r\n"
                        + "Content-Type: text/plain\r\n"
                        + "\r\n"
                        + "\"John Doe\"\r\n"
                        + boundary
                        + "\r\n"
                        + "Content-Disposition: form-data; name=\"file\"; filename=\"SampleZAPFile\"\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "\r\n"
                        + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eu tortor efficitur\r\n"
                        + boundary
                        + "--",
                requestBody);
    }

    @Test
    void shouldGenerateContentTypeObjectMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/multipartObject",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/multipartObject")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("Content-Type: application/json"));
    }

    @Test
    void shouldGenerateContentTypeBinaryMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/multipartBinary",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/multipartBinary")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("Content-Type: application/octet-stream"));
    }

    @Test
    void shouldGenerateContentTypeArrayMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/multipartArray",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/multipartArray")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("Content-Type: application/json"));
    }

    @Test
    void shouldGenerateContentTypeOtherMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        null,
                                        openAPI.getPaths()
                                                .get("/v3/openapi/multipartOther")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("Content-Type: text/plain"));
    }

    @Test
    void shouldEncodeContentTypeForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/image",
                                        openAPI.getPaths().get("/v3/openapi/image").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains(BodyGenerator.IMAGE_FILE_CONTENTS));
    }

    @Test
    void shouldEncodeCustomHeaderStringForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/headerString",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/headerString")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("X-Custom-Header: \"John Doe\""));
    }

    @Test
    void shouldEncodeCustomHeaderNumberForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/headerNumber",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/headerNumber")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("X-Custom-Header: 1.2"));
    }

    @Test
    void shouldEncodeCustomHeaderObjectForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/headerObject",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/headerObject")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(
                requestBody.contains(
                        "X-Custom-Header: {\"category\":\"John Doe\",\"height\":1.2,\"weight\":1.2}"));
    }

    @Test
    void shouldEncodeCustomHeaderBooleanForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/headerBoolean",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/headerBoolean")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("X-Custom-Header: true"));
    }

    @Test
    void shouldEncodeCustomHeaderAllForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/headerAll",
                                        openAPI.getPaths().get("/v3/openapi/headerAll").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains("X-Custom-Header-One: \"John Doe\""));
        assertTrue(requestBody.contains("X-Custom-Header-Two: 1.2"));
        assertTrue(
                requestBody.contains("X-Custom-Header-Three: {\"name\":\"John Doe\",\"age\":1.2}"));
        assertTrue(requestBody.contains("X-Custom-Header-Four: true"));
    }

    @Test
    void shouldEncodeContentTypeAndCustomHeaderForMultipartData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_multipart_with_encoding.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/imageAndHeaders",
                                        openAPI.getPaths()
                                                .get("/v3/openapi/imageAndHeaders")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();
        assertTrue(requestBody.contains(BodyGenerator.IMAGE_FILE_CONTENTS));
        assertTrue(requestBody.contains("X-Custom-Header: \"John Doe\""));
    }

    @Test
    void testAllOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_allof_schema.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        assertEquals(
                "{\"pet_type\":\"John Doe\",\"hunts\":true,\"age\":10,\"bark\":true,\"breed\":\"Dingo\"}",
                requestBody);
    }

    @Test
    void testOneOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_oneof_schema.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        assertEquals("{\"hunts\":true,\"age\":10}", requestBody);
    }

    @Test
    void testAnyOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_anyof_schema.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        assertEquals("{\"age\":10,\"nickname\":\"John Doe\"}", request);
    }

    @Test
    void testNot() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_not_schema.yaml");
        String requestType =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        assertEquals("{\"pet_type\":\"John Doe\"}", requestType);
        assertNotEquals("{\"pet_type\":1}", requestType);
        String requestAge =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getGet(), null),
                                generators)
                        .getBody();
        assertEquals("{\"age\":10,\"nickname\":\"John Doe\"}", requestAge);
        assertNotEquals("{\"age\":\"10\",\"nickname\":\"John Doe\"}", requestAge);
    }

    @Test
    void shouldReadAdditionalPropertiesIfNoProperties() throws IOException {
        OpenAPI openAPI = parseResource("Schema_with_additional_properties.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v4/endpoint",
                                        openAPI.getPaths().get("/v4/endpoint").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals(
                "[{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"]},{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"]}]",
                request);
    }

    @Test
    void shouldReadAdditionalMapString() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_map.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/mapString",
                                        openAPI.getPaths().get("/v3/openapi/mapString").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals("{\"name\":\"John Doe\",\"params\":{\"John Doe\":\"John Doe\"}}", request);
    }

    @Test
    void shouldReadAdditionalMapNumber() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_map.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/mapNumber",
                                        openAPI.getPaths().get("/v3/openapi/mapNumber").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals("{\"name\":\"John Doe\",\"params\":{\"John Doe\":1.2}}", request);
    }

    @Test
    void shouldReadAdditionalMapBoolean() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_map.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/mapBoolean",
                                        openAPI.getPaths().get("/v3/openapi/mapBoolean").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals("{\"name\":\"John Doe\",\"params\":{\"John Doe\":true}}", request);
    }

    @Test
    void shouldReadAdditionalMapObject() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_map.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v3/openapi/mapObject",
                                        openAPI.getPaths().get("/v3/openapi/mapObject").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals(
                "{\"name\":\"John Doe\",\"params\":{\"John Doe\":{\"name\":\"John Doe\"}}}",
                request);
    }

    @Test
    void shouldUseExample() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-example",
                                        openAPI.getPaths().get("/pets-with-example").getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals("{\"age\":3,\"name\":\"Fluffy\"}", request);
    }

    @Test
    void shouldUseJsonMediaTypeExamples() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-examples",
                                        openAPI.getPaths()
                                                .get("/pets-with-json-media-type-examples")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals("{\"age\":6,\"name\":\"Big Fluffy\"}", request);
    }

    @Test
    void shouldUseJsonMediaTypeExample() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-examples",
                                        openAPI.getPaths()
                                                .get("/pets-with-json-media-type-example")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals("{\"age\":1,\"name\":\"Small Fluffy\"}", request);
    }

    @Test
    void shouldGenerateArraysFromExamples() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-array-example",
                                        openAPI.getPaths()
                                                .get("/pets-with-array-example")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals("[{\"age\":3,\"name\":\"Fluffy\"},{\"age\":3,\"name\":\"Fluffy\"}]", request);
    }

    @Test
    void shouldGenerateArraysFromFullArrayExampleFormattedAsString() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-array-full-example-string",
                                        openAPI.getPaths()
                                                .get("/pets-with-array-full-example-string")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals(
                "[{\"age\":3,\"name\":\"Fluffy\"},{\"age\":512,\"name\":\"Fawkes\"}]", request);
    }

    @Test
    void shouldGenerateArraysFromFullArrayExampleFormattedAsYAML() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_examples.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets-with-array-full-example-yaml",
                                        openAPI.getPaths()
                                                .get("/pets-with-array-full-example-yaml")
                                                .getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals(
                "[{\"age\":3,\"name\":\"Fluffy\"},{\"age\":512,\"name\":\"Fawkes\"}]", request);
    }

    @Test
    void shouldGenerateBodyWithNoSchema() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_no_schema.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/media-type-no-schema",
                                        openAPI.getPaths().get("/media-type-no-schema").getPost(),
                                        null),
                                generators)
                        .getBody();

        assertEquals("", request);
    }

    @Test
    void shouldNotGenerateContentForApplicationXml() throws IOException {
        // Given
        OpenAPI definition = parseResource("openapi_xml_bodies.yaml");
        OperationModel operationModel =
                new OperationModel("/xml", definition.getPaths().get("/xml").getPost(), null);
        // When
        String content = new RequestModelConverter().convert(operationModel, generators).getBody();
        // Then
        assertThat(content, is(emptyString()));
        assertThat(
                generators.getErrorMessages(),
                contains(
                        "Not generating request body for operation xml, the content type application/xml is not supported."));
    }

    @Test
    void shouldGenerateStringTypeForInvalidPropertyType() throws IOException {
        // Given
        OpenAPI openAPI = parseResource("Schema_invalid_property_type.yaml");
        // When
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v4/endpoint",
                                        openAPI.getPaths().get("/v4/endpoint").getPost(),
                                        null),
                                generators)
                        .getBody();
        // Then
        assertEquals(
                "[{\"type\":\"John Doe\",\"tags\":[\"John Doe\"],\"includes\":\"John Doe\",\"metadata\":\"John Doe\",\"extra\":{},\"filtered_keys\":[\"John Doe\"]},{\"type\":\"John Doe\",\"tags\":[\"John Doe\"],\"includes\":\"John Doe\",\"metadata\":\"John Doe\",\"extra\":{},\"filtered_keys\":[\"John Doe\"]}]",
                request);
    }

    @Test
    void shouldGenerateNestedMapProperties() throws IOException {
        OpenAPI openAPI = parseResource("Schema_with_nested_map_properties.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/v4/endpoint",
                                        openAPI.getPaths().get("/v4/endpoint").getPost(),
                                        null),
                                generators)
                        .getBody();
        assertEquals(
                "[{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"],\"io\":[{\"input\":{\"name\":\"John Doe\",\"desc\":\"John Doe\",\"subthing\":{\"thing1\":\"John Doe\",\"thing2\":\"John Doe\"}},\"output\":{\"name\":\"John Doe\",\"desc\":\"John Doe\"}}]},{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"],\"io\":[{\"input\":{\"name\":\"John Doe\",\"desc\":\"John Doe\",\"subthing\":{\"thing1\":\"John Doe\",\"thing2\":\"John Doe\"}},\"output\":{\"name\":\"John Doe\",\"desc\":\"John Doe\"}}]}]",
                request);
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
