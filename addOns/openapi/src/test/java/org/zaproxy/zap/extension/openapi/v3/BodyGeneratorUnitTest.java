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

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;
import org.zaproxy.zap.extension.openapi.converter.swagger.RequestModelConverter;
import org.zaproxy.zap.extension.openapi.generators.Generators;

public class BodyGeneratorUnitTest {
    Generators generators;

    @Before
    public void init() {
        generators = new Generators(null);
    }

    @Test
    public void shouldGenerateArrayOfStrings() throws IOException {
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
        Assert.assertEquals("[\"John Doe\",\"John Doe\"]", jsonArray);
    }

    @Test
    public void shouldGenerateArrayOfEnums() throws IOException {
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
        Assert.assertEquals("[\"available\",\"available\"]", jsonArray);
    }

    @Test
    public void shouldGenerateJsonObject() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");

        String jsonString =
                generators
                        .getBodyGenerator()
                        .generate(openAPI.getComponents().getSchemas().get("User"));
        String output =
                "{\"id\":10,\"username\":\"John Doe\",\"firstName\":\"John Doe\",\"lastName\":\"John Doe\","
                        + "\"email\":\"John Doe\",\"password\":\"John Doe\",\"phone\":\"John Doe\",\"userStatus\":10}";
        Assert.assertEquals(output, jsonString);
    }

    @Test
    public void objectSchemaWithoutProperties() throws IOException {
        OpenAPI openAPI = parseResource("Object_schema_without_properties.json");

        String jsonString =
                generators
                        .getBodyGenerator()
                        .generate(openAPI.getComponents().getSchemas().get("credentials"));
        String output = "{\"userName\":\"John Doe\",\"password\":\"John Doe\"}";
        Assert.assertEquals(output, jsonString);
    }

    @Test
    public void shouldHandleRequestBodyRef() throws IOException {
        OpenAPI openAPI = parseResource("PetStore_defn.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        null, openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        Assert.assertEquals(
                "{\"id\":10,\"category\":{\"id\":10,\"name\":\"John Doe\"},\"name\":\"John Doe\",\"photoUrls\":[\"John Doe\"],\"tags\":[{\"id\":10,\"name\":\"John Doe\"}],\"status\":\"available\"}",
                requestBody);
    }

    @Test
    public void shouldGenerateFormData() throws IOException {
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
        Assert.assertEquals("name=name&status=status", requestBody);
    }

    @Test
    public void complexObjectInFormData() throws IOException {
        OpenAPI openAPI = parseResource("Complex_object_in_form_data.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pet", openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        Assert.assertEquals(
                "p1=p1&p2=%7B%22id%22%3A10%2C%22category%22%3A%7B%22id%22%3A10%2C%22name%22%3A%22John+Doe%22%7D%2C%22name%22%3A%22John+Doe%22%2C%22photoUrls%22%3A%5B%22John+Doe%22%5D%2C%22tags%22%3A%5B%7B%22id%22%3A10%2C%22name%22%3A%22John+Doe%22%7D%5D%7D",
                requestBody);
    }

    @Test
    public void arrayInFormData() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_with_array_in_form.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pet", openAPI.getPaths().get("/pet").getPost(), null),
                                generators)
                        .getBody();
        Assert.assertEquals("somearray=%5B1.2%2C1.2%5D", requestBody);
    }

    @Test
    public void testAllOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_allof_schema.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        Assert.assertEquals(
                "{\"pet_type\":\"John Doe\",\"hunts\":true,\"age\":10,\"bark\":true,\"breed\":\"Dingo\"}",
                requestBody);
    }

    @Test
    public void testOneOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_oneof_schema.yaml");
        String requestBody =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        Assert.assertEquals("{\"hunts\":true,\"age\":10}", requestBody);
    }

    @Test
    public void testAnyOf() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_anyof_schema.yaml");
        String request =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        Assert.assertEquals("{\"age\":10,\"nickname\":\"John Doe\"}", request);
    }

    @Test
    public void testNot() throws IOException {
        OpenAPI openAPI = parseResource("OpenApi_defn_not_schema.yaml");
        String requestType =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getPatch(), null),
                                generators)
                        .getBody();
        Assert.assertEquals("{\"pet_type\":\"John Doe\"}", requestType);
        Assert.assertNotEquals("{\"pet_type\":1}", requestType);
        String requestAge =
                new RequestModelConverter()
                        .convert(
                                new OperationModel(
                                        "/pets", openAPI.getPaths().get("/pets").getGet(), null),
                                generators)
                        .getBody();
        Assert.assertEquals("{\"age\":10,\"nickname\":\"John Doe\"}", requestAge);
        Assert.assertNotEquals("{\"age\":\"10\",\"nickname\":\"John Doe\"}", requestAge);
    }

    @Test
    public void shouldReadAdditionalPropertiesIfNoProperties() throws IOException {
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
        Assert.assertEquals(
                "[{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"]},{\"type\":\"John Doe\",\"filtered_keys\":[\"John Doe\"]}]",
                request);
    }

    @Test
    public void shouldReadAdditionalMapString() throws IOException {
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
        Assert.assertEquals(
                "{\"name\":\"John Doe\",\"params\":{\"John Doe\":\"John Doe\"}}", request);
    }

    @Test
    public void shouldReadAdditionalMapNumber() throws IOException {
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
        Assert.assertEquals("{\"name\":\"John Doe\",\"params\":{\"John Doe\":1.2}}", request);
    }

    @Test
    public void shouldReadAdditionalMapBoolean() throws IOException {
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
        Assert.assertEquals("{\"name\":\"John Doe\",\"params\":{\"John Doe\":true}}", request);
    }

    @Test
    public void shouldReadAdditionalMapObject() throws IOException {
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
        Assert.assertEquals(
                "{\"name\":\"John Doe\",\"params\":{\"John Doe\":{\"name\":\"John Doe\"}}}",
                request);
    }

    private OpenAPI parseResource(String fileName) throws IOException {
        ParseOptions options = new ParseOptions();
        options.setResolveFully(true);
        String defn =
                FileUtils.readFileToString(
                        new File(this.getClass().getResource(fileName).getFile()), "UTF-8");
        return new OpenAPIV3Parser().readContents(defn, new ArrayList<>(), options).getOpenAPI();
    }
}
