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
package org.zaproxy.addon.commonlib.http;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.StringEscapeUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.testutils.TestUtils;

class ComparableResponseUnitTest extends TestUtils {

    private static final String LOREM_FIVE_PARA =
            "\n"
                    + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam suscipit scelerisque dignissim. Ut pulvinar, erat vitae tincidunt ornare, diam lacus varius eros, sed fringilla felis est ut erat. Pellentesque sed ante ac velit pretium sodales. Quisque sed neque non diam finibus vehicula. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia curae; Vestibulum blandit nunc nec condimentum molestie. Fusce mattis nulla ultrices, congue nulla eu, imperdiet odio. Fusce condimentum est nec gravida blandit. Fusce laoreet sed velit eget pharetra.\n"
                    + "Aliquam erat volutpat. In ullamcorper tristique metus, bibendum consectetur sem. Maecenas vulputate felis eros, id pharetra ex finibus nec. Phasellus nulla ante, dignissim ut sapien vitae, gravida interdum felis. Donec consequat luctus augue maximus facilisis. Donec vitae magna ex. Vestibulum luctus, leo in dignissim dignissim, lacus urna elementum nulla, non ultricies erat nunc at orci. Sed tellus dolor, maximus non maximus non, congue vitae turpis. In tincidunt nec ligula quis finibus. Mauris nibh leo, bibendum sed pretium quis, vestibulum tempor nunc. Duis elit ipsum, pellentesque a lacinia quis, sollicitudin sed nisl.\n"
                    + "Fusce venenatis ante finibus ornare euismod. Cras magna elit, suscipit sit amet ultrices et, imperdiet sit amet ante. Cras molestie a nulla in cursus. Nullam sem mauris, posuere in bibendum non, mattis eu purus. Phasellus bibendum pharetra pulvinar. Pellentesque tempus ligula id nibh aliquam ultricies. Donec non nibh at tellus pretium convallis. Cras tempus tortor sit amet tincidunt varius. Nam ullamcorper interdum ipsum et pretium. Curabitur tincidunt felis eget blandit placerat. Maecenas molestie luctus finibus. Nulla et accumsan ex. Ut hendrerit laoreet mi sit amet fermentum. Phasellus ut enim eu libero ullamcorper pulvinar sed id purus. Aenean dolor urna, lacinia pulvinar urna sed, aliquam ullamcorper sapien.\n"
                    + "Cras luctus finibus gravida. Nunc interdum, nunc sed scelerisque tristique, sem est condimentum felis, sit amet euismod mauris odio quis mauris. Sed sed blandit urna, et volutpat velit. Sed ante tortor, dictum vel suscipit eu, convallis ut neque. Fusce et odio porttitor, auctor nisl quis, rhoncus lectus. Integer ut justo id metus lacinia feugiat. Nullam non ante eget justo luctus tempor. Cras ante justo, consequat efficitur dui nec, vestibulum pulvinar orci. Praesent ornare tortor ut vulputate porttitor. Aenean faucibus ligula id tortor hendrerit, eget iaculis lacus dapibus.\n"
                    + "Suspendisse potenti. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nam ac feugiat tortor, sed sollicitudin purus. Proin nec ultricies neque. Fusce in magna dui. Pellentesque dictum tellus ac ex lobortis commodo. Nulla condimentum gravida turpis, scelerisque pulvinar dui sagittis vitae. Sed sed sem interdum, auctor eros vel, vehicula neque. Quisque nec felis tincidunt, dapibus lacus at, posuere mauris. Nunc ultrices sit amet nulla nec mattis. Nam consequat diam pellentesque quam lacinia, eget consectetur lorem dapibus.";
    private static final String HTML_HELLO_WORLD =
            "<html>\n"
                    + " <head>\n"
                    + " </head>\n"
                    + " <body>\n"
                    + "   <h1>Hello World<h1>\n"
                    + " </body>\n"
                    + "</html>";
    private static final String JSON_HELLO_WORLD = "{\"message\": \"Hello World\"}";

    private static HttpMessage createBasicMessage() {
        return createBasicMessage("", true);
    }

    private static HttpMessage createBasicMessage(String body) {
        return createBasicMessage(body, true);
    }

    private static HttpMessage createBasicMessage(String body, boolean setContentType) {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        try {
            requestHeader.setURI(new URI("http://example.com", false));
        } catch (URIException | NullPointerException e) {
            // Ignore
        }
        HttpMessage msg = new HttpMessage();
        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        if (setContentType) {
            msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
        }
        msg.setResponseBody(body);
        return msg;
    }

    private static HttpMessage createLongResponseMessage() {
        return createBasicMessage(LOREM_FIVE_PARA);
    }

    private static HttpMessage createShortResponseMessage() {
        return createBasicMessage("Hello World!");
    }

    @Test
    void sameMessagesShouldMatch() {
        // Given
        HttpMessage msg = createBasicMessage();
        ComparableResponse response1 = new ComparableResponse(msg, "A");
        ComparableResponse response2 = response1;
        // When
        float comparison = response1.compareWith(response2);
        // Then
        assertEquals(1, comparison);
    }

    @Test
    void sameStatusCodesShouldMatch() {
        // Given
        HttpMessage msg = createBasicMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.statusCodeHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void differentStatusCodesShouldMismatch() {
        // Given
        HttpMessage msg = createBasicMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        msg.getResponseHeader().setStatusCode(500);
        ComparableResponse response2 = new ComparableResponse(msg, null);
        // When
        float result = ComparableResponse.statusCodeHeuristic(response1, response2);
        // Then
        assertEquals(0f, result);
    }

    @Test
    void messagesWithOnlyDifferentStatusCodesShouldMismatch() {
        // Given
        HttpMessage msg = createBasicMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        msg.getResponseHeader().setStatusCode(500);
        ComparableResponse response2 = new ComparableResponse(msg, null);
        // When
        float comparison = response1.compareWith(response2);
        // Then
        assertEquals(0, comparison);
    }

    @Test
    void sameContentShouldMatchWordCount() {
        // Given
        HttpMessage msg = createShortResponseMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.wordCountHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void sameContentShouldMatchLineCount() {
        // Given
        HttpMessage msg = createLongResponseMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.lineCountHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"test"})
    void sameContentShouldMatchInputReflectionHeuristic(String valueSent) {
        // Given
        HttpMessage msg = createLongResponseMessage();
        ComparableResponse response1 = new ComparableResponse(msg, valueSent);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void differentContentShouldMatchInputReflectionHeuristicWhenNoReflection() {
        // Given
        HttpMessage msg = createLongResponseMessage();
        HttpMessage msg2 = createShortResponseMessage();
        ComparableResponse response1 = new ComparableResponse(msg, "foo");
        ComparableResponse response2 = new ComparableResponse(msg2, "bar");
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void sameContentShouldMatchInputReflectionHeuristicEvenWithDifferentSentValues() {
        // Given
        HttpMessage msg = createBasicMessage(LOREM_FIVE_PARA);
        HttpMessage msg2 = createBasicMessage(LOREM_FIVE_PARA);
        ComparableResponse response1 = new ComparableResponse(msg, "foo");
        ComparableResponse response2 = new ComparableResponse(msg2, "bar");
        ;
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void sameContentShouldMatchInputReflectionHeuristicWhenSubstringSent() {
        // Given
        HttpMessage msg = createBasicMessage(LOREM_FIVE_PARA + "test");
        HttpMessage msg2 = createBasicMessage(LOREM_FIVE_PARA + "footest");
        ComparableResponse response1 = new ComparableResponse(msg, "test");
        ComparableResponse response2 = new ComparableResponse(msg2, "footest");
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void
            differentContentShouldPartiallyMatchInputReflectionHeuristicWhenSentStringReflectedInOneMessageHtmlEscaped() {
        // Given
        HttpMessage msg = createBasicMessage(LOREM_FIVE_PARA);
        HttpMessage msg2 =
                createBasicMessage(
                        LOREM_FIVE_PARA.replaceAll(
                                "\n", StringEscapeUtils.escapeHtml("\n\"test\"")));
        ComparableResponse response1 = new ComparableResponse(msg, "\"test\"");
        ComparableResponse response2 = new ComparableResponse(msg2, "test");
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(0.5454545617103577f, result);
    }

    private static Stream<Arguments> provideMixedReflectedResponseContentPairs() {
        return Stream.of(
                Arguments.of(
                        createBasicMessage(LOREM_FIVE_PARA),
                        createBasicMessage(LOREM_FIVE_PARA.replaceAll("\n", "\ntest"))),
                Arguments.of(
                        createBasicMessage(LOREM_FIVE_PARA.replaceAll("\n", "\ntest")),
                        createBasicMessage(LOREM_FIVE_PARA)));
    }

    @ParameterizedTest
    @MethodSource("provideMixedReflectedResponseContentPairs")
    void
            differentContentShouldPartiallyMatchInputReflectionHeuristicWhenSentStringReflectedInOneMessage(
                    HttpMessage msg, HttpMessage msg2) {
        // Given
        ComparableResponse response1 = new ComparableResponse(msg, "test");
        ComparableResponse response2 = new ComparableResponse(msg2, "test");
        // When
        float result = ComparableResponse.inputReflectionHeuristic(response1, response2);
        // Then
        assertEquals(0.09090909361839294f, result);
    }

    private static Stream<Arguments> provideMixedLongAndShortResponseContentPairs() {
        return Stream.of(
                Arguments.of(createShortResponseMessage(), createLongResponseMessage()),
                Arguments.of(createLongResponseMessage(), createShortResponseMessage()));
    }

    @ParameterizedTest
    @MethodSource("provideMixedLongAndShortResponseContentPairs")
    void differentContentShouldMismatchWordCount(HttpMessage msg, HttpMessage msg2) {
        // Given
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.wordCountHeuristic(response1, response2);
        // Then
        assertEquals(0.0044742729514837265f, result);
    }

    @ParameterizedTest
    @MethodSource("provideMixedLongAndShortResponseContentPairs")
    void differentContentShouldMismatchLineCount(HttpMessage msg, HttpMessage msg2) {
        // Given
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.lineCountHeuristic(response1, response2);
        // Then
        assertEquals(0.1666666716337204f, result);
    }

    @Test
    void emptyHeadersShouldMatch() {
        // Given
        HttpMessage msg = createBasicMessage();
        try {
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n\r\n");
        } catch (HttpMalformedHeaderException e) {
            // Ignore
        }
        HttpMessage msg2 = msg.cloneAll();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.headersCompareHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    private static Stream<Arguments> provideResponseHeaderPairs() {
        HttpMessage msg = createBasicMessage();
        try {
            msg.setResponseHeader("HTTP/1.1 200 OK\r\n\r\n");
        } catch (HttpMalformedHeaderException e) {
            // Ignore
        }
        HttpMessage msg2 = msg.cloneAll();
        msg2.getResponseHeader().addHeader("Server", "Foo 1.0");
        msg2.getResponseHeader().addHeader("X-Test-Header", "TestValue");
        return Stream.of(Arguments.of(msg, msg2), Arguments.of(msg2, msg));
    }

    @ParameterizedTest
    @MethodSource("provideResponseHeaderPairs")
    void differentHeadersShouldMismatchHeaderCheck(HttpMessage msg, HttpMessage msg2) {
        // Given
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.headersCompareHeuristic(response1, response2);
        // Then
        assertEquals(0f, result);
    }

    @ParameterizedTest
    @MethodSource("provideResponseHeaderPairs")
    void partiallyDifferentHeadersShouldPartiallyMatchHeaderCheck(
            HttpMessage msg, HttpMessage msg2) {
        // Given
        msg.getResponseHeader().addHeader("Server", "Foo 1.0");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.headersCompareHeuristic(response1, response2);
        // Then
        assertEquals(0.5f, result);
    }

    @ParameterizedTest
    @MethodSource("provideResponseHeaderPairs")
    void partiallyDifferentHeadersIncludingDynamicShouldPartiallyMatchHeaderCheck(
            HttpMessage msg, HttpMessage msg2) {
        // Given
        msg.getResponseHeader().addHeader("Server", "Foo 1.0");
        msg2.getResponseHeader().addHeader("Expires", "Wed, 21 Oct 2015 07:28:00 GMT");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.headersCompareHeuristic(response1, response2);
        // Then
        assertEquals(0.5f, result);
    }

    @Test
    void sameContentShouldMatchRelevantWordCount() {
        // Given
        HttpMessage msg = createShortResponseMessage();
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void sameContentShouldMatchRelevantWordCountWhenBothContainRelevantWords() {
        // Given
        HttpMessage msg = createBasicMessage("Hello World! unknown");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void sameContentShouldMismatchRelevantWordCountWhenOneContainsRelevantWords() {
        // Given
        HttpMessage msg = createBasicMessage("Hello World! unknown");
        HttpMessage msg2 = createBasicMessage("Hello World!");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        ;
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(0f, result);
    }

    private static Stream<Arguments> provideMixedRelevantWordPairs() {
        return Stream.of(Arguments.of(null, "unknown"), Arguments.of("unknown", null));
    }

    @ParameterizedTest
    @MethodSource("provideMixedRelevantWordPairs")
    void sameContentShouldMismatchRelevantWordCountWhenOneContainsRelevantWordsIgnoringSentKeyword(
            String valueSent, String valueSent2) {
        // Given
        HttpMessage msg = createBasicMessage("Hello World! error");
        HttpMessage msg2 = createBasicMessage("Hello World!");
        ComparableResponse response1 = new ComparableResponse(msg, valueSent);
        ComparableResponse response2 = new ComparableResponse(msg2, valueSent2);
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(0f, result);
    }

    private static Stream<Arguments> provideMixedRelevantWordPairsWithOverlap() {
        return Stream.of(
                Arguments.of("error", "error unknown"), Arguments.of("error unknown", "error"));
    }

    @ParameterizedTest
    @MethodSource("provideMixedRelevantWordPairsWithOverlap")
    void shouldPartiallyMatchRelevantWordCountWhenOneContainsASubsetOfRelevantWords(
            String content, String content2) {
        // Given
        HttpMessage msg = createBasicMessage("Hello World! " + content);
        HttpMessage msg2 = createBasicMessage("Hello World! " + content2);
        ComparableResponse response1 = new ComparableResponse(msg, "");
        ComparableResponse response2 = new ComparableResponse(msg2, "");
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(0.5f, result);
    }

    @ParameterizedTest
    @MethodSource("provideMixedRelevantWordPairsWithOverlap")
    void shouldMismatchRelevantWordCountWhenOneContainsASubsetOfRelevantWordsValueSentInBoth(
            String content, String content2) {
        // Given - Both contain "error"
        HttpMessage msg = createBasicMessage("Hello World! " + content);
        HttpMessage msg2 = createBasicMessage("Hello World! " + content2);
        ComparableResponse response1 = new ComparableResponse(msg, "error");
        ComparableResponse response2 = new ComparableResponse(msg2, "error");
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(0.0f, result);
    }

    @ParameterizedTest
    @MethodSource("provideMixedRelevantWordPairsWithOverlap")
    void shouldMatchRelevantWordCountWhenOneContainsASubsetOfRelevantWordsValueSentOnlyInOne(
            String content, String content2) {
        // Given - One contains "unknown"
        HttpMessage msg = createBasicMessage("Hello World! " + content);
        HttpMessage msg2 = createBasicMessage("Hello World! " + content2);
        ComparableResponse response1 = new ComparableResponse(msg, "unknown");
        ComparableResponse response2 = new ComparableResponse(msg2, "unknown");
        // When
        float result = ComparableResponse.relevantKeywordsCountHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    private static Stream<Arguments> provideMixedContentPairs() {
        return Stream.of(
                Arguments.of(HTML_HELLO_WORLD, "medium.html", "text/html"),
                Arguments.of(JSON_HELLO_WORLD, "petstore.json", "application/json"));
    }

    @ParameterizedTest
    @MethodSource("provideMixedContentPairs")
    void differentContentShouldMismatchTreeStructure(
            String content, String file, String contentType) {
        // Given
        HttpMessage msg = createBasicMessage(content);
        HttpMessage msg2 = createBasicMessage(getHtml(file));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, contentType);
        msg2.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, contentType);
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(0.0f, result);
    }

    private static Stream<Arguments> provideFileNames() {
        return Stream.of(
                Arguments.of("medium.html", "text/html"),
                Arguments.of("petstore.json", "application/json"));
    }

    @ParameterizedTest
    @MethodSource("provideFileNames")
    void sameContentShouldMatchTreeStructure(String file, String contentType) {
        // Given
        HttpMessage msg = createBasicMessage(getHtml(file));
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, contentType);
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = response1;
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    @Test
    void shouldMatchTreeStructureWhenNeitherHaveContentType() {
        // Given
        HttpMessage msg = createBasicMessage(HTML_HELLO_WORLD, false);
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    private static Stream<Arguments> provideMixedNullContentTypePairs() {
        HttpMessage msg = createBasicMessage(HTML_HELLO_WORLD, true);
        HttpMessage msg2 = createBasicMessage(HTML_HELLO_WORLD, false);
        return Stream.of(Arguments.of(msg, msg2), Arguments.of(msg2, msg));
    }

    @ParameterizedTest
    @MethodSource("provideMixedNullContentTypePairs")
    void shouldMismatchTreeStructureWhenOnlyOneMessageHasContentType() {
        // Given
        HttpMessage msg = createBasicMessage(HTML_HELLO_WORLD, false);
        HttpMessage msg2 = createBasicMessage(HTML_HELLO_WORLD, true);
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(0.0f, result);
    }

    @Test
    void shouldMismatchTreeStructureWhenBothMessagesHaveDifferentContentTypes() {
        // Given
        HttpMessage msg = createBasicMessage(JSON_HELLO_WORLD, false);
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "application/json");
        HttpMessage msg2 = createBasicMessage(HTML_HELLO_WORLD, true);
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(0.0f, result);
    }

    @Test
    void shouldMatchTreeStructureWhenBothMessagesHaveZeroStructure() {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }

    private static Stream<Arguments> provideMixedZeroStructurePairs() {
        HttpMessage msg = new HttpMessage();
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "text/html");
        HttpMessage msg2 = createBasicMessage(HTML_HELLO_WORLD, true);
        return Stream.of(Arguments.of(msg, msg2), Arguments.of(msg2, msg));
    }

    @ParameterizedTest
    @MethodSource("provideMixedZeroStructurePairs")
    void shouldMismatchTreeStructureWhenOnlyOneMessagesHasStructure(
            HttpMessage msg, HttpMessage msg2) {
        // Given
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg2, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(0.0f, result);
    }

    @Test
    void shouldMatchTreeStructureWhenNeitherMessagesHasRelevantContentTYpe() {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.getResponseHeader().addHeader(HttpHeader.CONTENT_TYPE, "image/gif");
        ComparableResponse response1 = new ComparableResponse(msg, null);
        ComparableResponse response2 = new ComparableResponse(msg, null);
        // When
        float result = ComparableResponse.bodyTreesStructureHeuristic(response1, response2);
        // Then
        assertEquals(1.0f, result);
    }
}
