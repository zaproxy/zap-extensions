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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.postman.models.AbstractItem;
import org.zaproxy.addon.postman.models.Body;
import org.zaproxy.addon.postman.models.Body.GraphQl;
import org.zaproxy.addon.postman.models.Item;
import org.zaproxy.addon.postman.models.ItemGroup;
import org.zaproxy.addon.postman.models.KeyValueData;
import org.zaproxy.addon.postman.models.PostmanCollection;
import org.zaproxy.addon.postman.models.Request;
import org.zaproxy.zap.testutils.TestUtils;

class PostmanParserUnitTest extends TestUtils {

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        mockMessages(new ExtensionPostman());
    }

    @AfterEach
    void teardown() throws Exception {
        stopServer();
    }

    static Stream<Arguments> extractionTestData() {
        Item item = new Item(new Request("https://example.com"));
        return Stream.of(
                arguments(new ArrayList<AbstractItem>(List.of()), 0),
                arguments(new ArrayList<AbstractItem>(List.of(item, item)), 2),
                arguments(
                        new ArrayList<AbstractItem>(
                                List.of(
                                        new ItemGroup(
                                                new ArrayList<AbstractItem>(List.of(item, item))))),
                        2),
                arguments(
                        new ArrayList<AbstractItem>(
                                List.of(
                                        item,
                                        new ItemGroup(new ArrayList<AbstractItem>(List.of(item))))),
                        2));
    }

    static Stream<Arguments> requestBodyTestData() throws URISyntaxException {
        Body rawBody = new Body(Body.RAW);
        rawBody.setRaw("raw-body");

        Body urlencodedBody = new Body(Body.URL_ENCODED);
        urlencodedBody.setUrlencoded(
                new ArrayList<>(
                        List.of(
                                new KeyValueData("key1", "value1"),
                                new KeyValueData("key2", "value2"))));

        Body formDataBody = new Body(Body.FORM_DATA);
        formDataBody.setFormData(
                new ArrayList<KeyValueData>(
                        List.of(
                                new KeyValueData("key1", "value1", "text"),
                                new KeyValueData("key2", "", "file"))));

        GraphQl graphQl = new GraphQl();
        graphQl.setQuery(
                "query getByArtist ($name: String!) {\r\n    queryArtists (byName: $name) {\r\n        name\r\n        image\r\n        albums {\r\n            name\r\n        }\r\n    }\r\n}");
        graphQl.setVariables("{\r\n    \"name\": \"{{artist}}\"\r\n}");

        Body graphQlBody = new Body(Body.GRAPHQL);
        graphQlBody.setGraphQl(graphQl);

        Body fileBody = new Body(Body.FILE);
        fileBody.setFile(new org.zaproxy.addon.postman.models.Body.File());

        return Stream.of(
                arguments(rawBody, "text/plain", "raw-body"),
                arguments(
                        urlencodedBody,
                        HttpRequestHeader.FORM_URLENCODED_CONTENT_TYPE,
                        "key1=value1&key2=value2"),
                arguments(
                        formDataBody,
                        "multipart/form-data; boundary=----BOUNDARY",
                        "------BOUNDARY"
                                + "\r\n"
                                + "Content-Disposition: form-data; name=\"key1\""
                                + "\r\n\r\n"
                                + "value1"
                                + "\r\n"
                                + "------BOUNDARY"
                                + "\r\n"
                                + "Content-Disposition: form-data; name=\"key2\"; filename=\"sampleFile.txt\""
                                + "\r\n"
                                + "content-type: text/plain"
                                + "\r\n\r\n"
                                + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eu tortor efficitur\n"
                                + "\r\n"
                                + "------BOUNDARY--"
                                + "\r\n"),
                arguments(
                        graphQlBody,
                        HttpHeader.JSON_CONTENT_TYPE,
                        "{"
                                + "\"query\":\"query getByArtist ($name: String!) {\r\n    queryArtists (byName: $name) {\r\n        name\r\n        image\r\n        albums {\r\n            name\r\n        }\r\n    }\r\n}\", "
                                        .replaceAll("\r\n", "\\\\r\\\\n")
                                + "\"variables\":{\"name\":\"{{artist}}\"}".replaceAll("\\s", "")
                                + "}"),
                arguments(
                        fileBody,
                        "text/plain",
                        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eu tortor efficitur\n"));
    }

    static Stream<Arguments> errorTestData() {
        final String IMPORT_FORMAT_ERROR = "postman.import.error.format";
        String noItemError = Constant.messages.getString("postman.import.error.noItem");
        return Stream.of(
                arguments(
                        "{\"item\":{}}",
                        List.of(
                                Constant.messages.getString(
                                        IMPORT_FORMAT_ERROR,
                                        "Unnamed Item",
                                        Constant.messages.getString(
                                                "postman.import.errorMsg.reqNotPresent")),
                                noItemError)),
                arguments(
                        "{\"item\":{\"name\":\"test\"}}",
                        List.of(
                                Constant.messages.getString(
                                        IMPORT_FORMAT_ERROR,
                                        "test",
                                        Constant.messages.getString(
                                                "postman.import.errorMsg.reqNotPresent")),
                                noItemError)),
                arguments(
                        "{\"item\":{\"request\":{\"method\":\"POST\"}}}",
                        List.of(
                                Constant.messages.getString(
                                        IMPORT_FORMAT_ERROR,
                                        "Unnamed Item",
                                        Constant.messages.getString(
                                                "postman.import.errorMsg.urlNotPresent")),
                                noItemError)),
                arguments(
                        "{\"item\":{\"request\":{\"url\":\"\"}}}",
                        List.of(
                                Constant.messages.getString(
                                        IMPORT_FORMAT_ERROR,
                                        "Unnamed Item",
                                        Constant.messages.getString(
                                                "postman.import.errorMsg.rawInvalid")),
                                noItemError)),
                arguments(
                        "{\"item\":{\"request\":{\"url\":\"https://example.com\",\"body\":{\"mode\":\"file\",\"file\":{\"src\":\"invalidPath\"}}}}}",
                        List.of(
                                Constant.messages.getString(
                                        "postman.import.warning",
                                        "Unnamed Item",
                                        NoSuchFileException.class.getName() + ": invalidPath"))));
    }

    static Stream<Arguments> variablesTestData() throws URISyntaxException {
        return Stream.of(
                // no pair
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "",
                        "{\"item\":{\"name\":\"{{name}}\"}}"),
                // single pair
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "name=someName",
                        "{\"item\":{\"name\":\"someName\"}}"),
                // multiple pairs
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\",\"request\":{\"url\":\"{{url}}\"}}}",
                        "url=https://example.com,name=someName",
                        "{\"item\":{\"name\":\"someName\",\"request\":{\"url\":\"https:\\/\\/example.com\"}}}"),
                // no separator
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "name",
                        "{\"item\":{\"name\":\"{{name}}\"}}"),
                // multiple separators
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "name=someName1=someName2",
                        "{\"item\":{\"name\":\"someName1=someName2\"}}"),
                // empty value
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "name=",
                        "{\"item\":{\"name\":\"\"}}"),
                // empty key
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "=someName",
                        "{\"item\":{\"name\":\"{{name}}\"}}"),
                // escaping check
                arguments(
                        "{\"item\":{\"name\":\"{{name}}\"}}",
                        "name=\\",
                        "{\"item\":{\"name\":\"\\\\\"}}"));
    }

    @Test
    void shouldFailWhenCollectionIsInvalidJson() throws Exception {
        PostmanParser parser = new PostmanParser();
        assertThrows(IOException.class, () -> parser.importCollection("{", "", false));
    }

    @Test
    void shouldParseWhenCollectionIsValidJson() throws Exception {
        PostmanParser parser = new PostmanParser();
        assertDoesNotThrow(() -> parser.parse("{}"));
    }

    @Test
    void shouldParseKnownAttributes() throws Exception {
        PostmanParser parser = new PostmanParser();
        String collectionJson = "{\"item\":true,\"variable\":\"\"}"; // Random types for leniency
        PostmanCollection collection = parser.parse(collectionJson);

        assertNotNull(collection.getItem());
        assertNotNull(collection.getVariable());
    }

    @Test
    void shouldIgnoreUnKnownAttributes() throws Exception {
        PostmanParser parser = new PostmanParser();
        String collectionJson = "{\"unKnown1\":true,\"unKnown2\":\"\"}";
        assertDoesNotThrow(() -> parser.parse(collectionJson));
    }

    @ParameterizedTest
    @MethodSource("extractionTestData")
    void shouldExtractHttpMessagesFromItems(List<AbstractItem> items, int numberOfitems)
            throws Exception {
        List<HttpMessage> httpMessages = new ArrayList<>();
        PostmanParser.extractHttpMessages(items, httpMessages);

        assertEquals(numberOfitems, httpMessages.size());
    }

    // The 'Content-Type' header gets set according to the mode of the request body, but if it's
    // explicitly defined in the request, that value will take precedence
    @Test
    void shouldNotSetContentTypeIfExplicitlySet() {
        Body body = new Body();
        body.setMode(Body.GRAPHQL);

        GraphQl graphQl = new GraphQl();
        graphQl.setQuery(
                "query getByArtist ($name: String!) {\r\n    queryArtists (byName: $name) {\r\n        name\r\n        image\r\n        albums {\r\n            name\r\n        }\r\n    }\r\n}");
        graphQl.setVariables("{\r\n    \"name\": \"{{artist}}\"\r\n}");

        body.setGraphQl(graphQl);

        Request req = new Request("https://example.com");
        req.setBody(body);
        req.setHeader(
                Collections.singletonList(
                        new KeyValueData(HttpRequestHeader.CONTENT_TYPE, "custom-content-type")));

        HttpMessage httpMessage = PostmanParser.extractHttpMessage(new Item(req));
        String contentType =
                httpMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_TYPE);

        assertEquals("custom-content-type", contentType);
    }

    @ParameterizedTest
    @MethodSource("requestBodyTestData")
    void shouldHandleRequestBodyModes(Body body, String contentType, String stringBody) {
        Request req = new Request("https://example.com");
        req.setBody(body);

        if (contentType.startsWith("multipart/form-data")) {
            Path path = getResourcePath("sampleFile.txt");
            String src = path.toAbsolutePath().toString();
            body.getFormData().get(1).setSrc(src);
        }

        if (contentType.equals("text/plain") && stringBody.startsWith("Lorem")) {
            Path path = getResourcePath("sampleFile.txt");
            String src = path.toAbsolutePath().toString();
            body.getFile().setSrc(src);
        }

        HttpMessage httpMessage = PostmanParser.extractHttpMessage(new Item(req));

        if (contentType.startsWith("multipart/form-data")) {
            String tempStringBody =
                    new String(httpMessage.getRequestBody().getContent(), StandardCharsets.UTF_8);
            String bodyFirstLine = tempStringBody.split("\r\n", 2)[0];
            String boundary = bodyFirstLine.split("------", 2)[1];
            contentType = contentType.replace("BOUNDARY", boundary);
            stringBody = stringBody.replace("BOUNDARY", boundary);
        }

        assertEquals(
                contentType,
                httpMessage.getRequestHeader().getHeader(HttpRequestHeader.CONTENT_TYPE));
        assertEquals(
                stringBody,
                new String(httpMessage.getRequestBody().getContent(), StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @MethodSource("errorTestData")
    void shouldGiveErrors(String collectionJson, List<String> expectedErrors)
            throws JsonProcessingException {
        PostmanParser parser = new PostmanParser();
        List<String> errors = new ArrayList<>();

        parser.getHttpMessages(collectionJson, "", errors);

        assertEquals(expectedErrors.size(), errors.size());
        for (int i = 0; i < errors.size(); i++) {
            assertEquals(expectedErrors.get(i), errors.get(i));
        }
    }

    @MethodSource("variablesTestData")
    void shouldReplaceValidVariables(
            String inputCollection, String variables, String expectedOutputCollection) {
        String outputCollection = PostmanParser.replaceVariables(inputCollection, variables);
        assertEquals(expectedOutputCollection, outputCollection);
    }

    static Stream<String> nullFieldValuesTestData() {
        String bodyBaseLeft = "{\"item\":{\"request\":{\"url\":\"https://example.com\"},\"body\":";
        String bodyBaseRight = "}}";
        return Stream.of(
                "{\"item\":null}",
                "{\"item\":{\"request\":null,\"name\":null}}",
                "{\"item\":{\"request\":{\"url\":null,\"method\":null,\"header\":null,\"body\":null}}}",
                "{\"item\":{\"request\":{\"url\":{\"raw\":null}}}}",
                "{\"item\":{\"request\":{\"url\":{\"raw\":\"https://example.com\",\"header\":{\"key\":null,\"value\":null}}}}}",
                bodyBaseLeft + "{\"mode\":null}" + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"raw\",\"raw\":null}" + bodyBaseRight,
                bodyBaseLeft
                        + "{\"mode\":\"raw\",\"raw\":\"some content\",\"options\":null}"
                        + bodyBaseRight,
                bodyBaseLeft
                        + "{\"mode\":\"raw\",\"raw\":\"some content\",\"options\":{\"raw\":null}}"
                        + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"urlencoded\",\"urlencoded\":null}" + bodyBaseRight,
                bodyBaseLeft
                        + "{\"mode\":\"urlencoded\",\"urlencoded\":{\"key\":null,\"value\":null}}"
                        + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"formdata\",\"formdata\":null}" + bodyBaseRight,
                bodyBaseLeft
                        + "{\"mode\":\"formdata\",\"formdata\":{\"key\":null,\"value\":null,\"src\":null,\"type\":null}}"
                        + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"file\",\"file\":null}" + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"file\",\"file\":{\"src\":null}}" + bodyBaseRight,
                bodyBaseLeft + "{\"mode\":\"raw\",\"graphql\":null}" + bodyBaseRight,
                bodyBaseLeft
                        + "{\"mode\":\"raw\",\"graphql\":{\"query\":null,\"variables\":null}}"
                        + bodyBaseRight);
    }

    @ParameterizedTest
    @MethodSource("nullFieldValuesTestData")
    void shouldNotFailForNullFieldValues(String collection) {
        PostmanParser parser = new PostmanParser();
        assertDoesNotThrow(() -> parser.importCollection(collection, "", false));
    }

    @Test
    void shouldReplaceJsonPathVars() throws JsonProcessingException {
        String collectionJson =
                "{\"item\":{\"request\":{\"url\":{\"raw\":\"https://example.com/:someKey\",\"variable\":{\"key\":\"someKey\",\"value\":\"somePath\"}}}}}";
        PostmanParser parser = new PostmanParser();
        List<HttpMessage> messages = parser.getHttpMessages(collectionJson, "", new ArrayList<>());

        assertEquals(
                "https://example.com/somePath",
                messages.get(0).getRequestHeader().getURI().toString());
    }

    static Stream<Arguments> jsonVarsTestData() {
        String value = "someValue";
        String variable = "\"variable\":[{\"key\":\"someKey\",\"value\":\"" + value + "\"}]";

        String url = "\"url\":\"https://example.com/{{someKey}}\"";
        String body = "\"body\":{\"mode\":\"raw\",\"raw\":\"Value is {{someKey}}\"}";
        String method = "\"method\":\"{{someKey}}\"";
        String header =
                "\"header\":{\"key\":\""
                        + HttpHeader.CONTENT_TYPE
                        + "\",\"value\":\"{{someKey}}\"}";

        String collectionWithCollectionVar =
                "{\"item\":{\"request\":{"
                        + url
                        + ","
                        + body
                        + ","
                        + method
                        + ","
                        + header
                        + "}},"
                        + variable
                        + "}";
        String collectionWithItemVar =
                "{\"item\":{\"request\":{"
                        + url
                        + ","
                        + body
                        + ","
                        + method
                        + ","
                        + header
                        + "},"
                        + variable
                        + "}}";
        String collectionWithItemGroupVar =
                "{\"item\":{\"item\":{\"request\":{"
                        + url
                        + ","
                        + body
                        + ","
                        + method
                        + ","
                        + header
                        + "}}},"
                        + variable
                        + "}";

        return Stream.of(
                arguments(collectionWithCollectionVar, value),
                arguments(collectionWithItemVar, value),
                arguments(collectionWithItemGroupVar, value));
    }

    @ParameterizedTest
    @MethodSource("jsonVarsTestData")
    void shouldReplaceJsonVars(String collection, String value) throws JsonProcessingException {
        PostmanParser parser = new PostmanParser();
        List<HttpMessage> messages = parser.getHttpMessages(collection, "", new ArrayList<>());
        HttpMessage message = messages.get(0);

        assertEquals(
                "https://example.com/" + value, message.getRequestHeader().getURI().toString());
        assertEquals("Value is " + value, message.getRequestBody().toString());
        assertEquals(value.toUpperCase(Locale.ROOT), message.getRequestHeader().getMethod());
        assertEquals(value, message.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE));
    }

    @Test
    void shouldFindItemUnderItemGroups() throws JsonProcessingException {
        // Given
        var collection =
                "{\n"
                        + "  \"item\" : [ {\n"
                        + "    \"name\" : \"JIM\",\n"
                        + "    \"item\" : [ {\n"
                        + "      \"name\" : \"BOB\",\n"
                        + "      \"request\" : {\n"
                        + "        \"method\" : \"GET\",\n"
                        + "        \"url\" : {\n"
                        + "          \"raw\" : \"https://example.com/\"\n"
                        + "        }\n"
                        + "      }\n"
                        + "    } ]\n"
                        + "  } ]\n"
                        + "}";
        PostmanParser parser = new PostmanParser();

        // When
        List<HttpMessage> messages = parser.getHttpMessages(collection, "", new ArrayList<>());

        // Then
        HttpMessage message = messages.get(0);
        assertEquals("https://example.com/", message.getRequestHeader().getURI().toString());
        assertEquals("GET", message.getRequestHeader().getMethod());
    }
}
