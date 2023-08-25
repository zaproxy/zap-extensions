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

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.postman.models.AbstractItem;
import org.zaproxy.addon.postman.models.Body;
import org.zaproxy.addon.postman.models.Body.FormData;
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
                new ArrayList<FormData>(
                        List.of(
                                new FormData("key1", "value1", "text"),
                                new FormData("key2", "", "file"))));

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

    @Test
    void shouldFailWhenCollectionIsInvalidJson() throws Exception {
        PostmanParser parser = new PostmanParser();
        assertThrows(IOException.class, () -> parser.importCollection("{"));
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
}
