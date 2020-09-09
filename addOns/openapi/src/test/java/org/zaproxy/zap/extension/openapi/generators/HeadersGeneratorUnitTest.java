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
package org.zaproxy.zap.extension.openapi.generators;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;

/** Unit test for {@link HeadersGenerator}. */
class HeadersGeneratorUnitTest {

    private DataGenerator dataGenerator;
    private HeadersGenerator headersGenerator;

    @BeforeEach
    void setup() {
        dataGenerator = mock(DataGenerator.class);
        headersGenerator = new HeadersGenerator(dataGenerator);
    }

    @Test
    void shouldNotGenerateContentTypeIfNoRequestBody() {
        // Given
        RequestBody request = null;
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, not(contains(header("Content-Type"))));
    }

    @Test
    void shouldNotGenerateContentTypeIfRequestHaveNoMediaTypes() {
        // Given
        RequestBody request = mockRequestWithMediaTypes((String[]) null);
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, not(contains(header("Content-Type"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/plain", "application/xml"})
    void shouldNotGenerateContentTypeIfNotJsonNorWwwFormUrlEncoded(String mediaType) {
        // Given
        RequestBody request = mockRequestWithMediaTypes(mediaType);
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, not(contains(header("Content-Type"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"text/json", "application/json", "application/json-x", "text/jSoN"})
    void shouldGenerateJsonBasedContentType(String mediaType) {
        // Given
        RequestBody request = mockRequestWithMediaTypes(mediaType);
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Content-Type", mediaType)));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {"application/x-www-form-urlencoded", "application/x-WWW-Form-UrlEncoded"})
    void shouldGenerateWwwFormUrlEncodedContentType(String mediaType) {
        // Given
        RequestBody request = mockRequestWithMediaTypes(mediaType);
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Content-Type", mediaType)));
    }

    @Test
    void shouldGenerateJustFirstSupportedContentType() {
        // Given
        RequestBody request =
                mockRequestWithMediaTypes("application/json", "application/x-www-form-urlencoded");
        Operation operation = mockOperationWithRequest(request);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateContentTypeHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Content-Type", "application/json")));
    }

    @Test
    void shouldAcceptAllContentsIfResponsesHaveNoContent() {
        // Given
        ApiResponse response1 = mockResponseWithMediaTypes((String[]) null);
        ApiResponse response2 = mockResponseWithMediaTypes((String[]) null);
        Operation operation = mockOperationWithResponses(response1, response2);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateAcceptHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Accept", "*/*")));
    }

    @Test
    void shouldAcceptContentPresentInResponse() {
        // Given
        ApiResponse response = mockResponseWithMediaTypes("text/plain");
        Operation operation = mockOperationWithResponses(response);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateAcceptHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Accept", "text/plain")));
    }

    @Test
    void shouldAcceptAllContentsPresentInResponse() {
        // Given
        ApiResponse response = mockResponseWithMediaTypes("text/x", "text/y");
        Operation operation = mockOperationWithResponses(response);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateAcceptHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Accept", "text/x, text/y")));
    }

    @Test
    void shouldAcceptAllContentsPresentInAllResponses() {
        // Given
        ApiResponse response1 = mockResponseWithMediaTypes("text/a1");
        ApiResponse response2 = mockResponseWithMediaTypes("text/b1", "text/b2");
        ApiResponse response3 = mockResponseWithMediaTypes("text/c1", "text/c2", "text/c3");
        Operation operation = mockOperationWithResponses(response1, response2, response3);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateAcceptHeaders(operation, headers);
        // Then
        assertThat(
                headers,
                contains(header("Accept", "text/a1, text/b1, text/b2, text/c1, text/c2, text/c3")));
    }

    @Test
    void shouldAcceptSameContentOnlyOnceEvenIfPresentMultipleTimes() {
        // Given
        ApiResponse response1 = mockResponseWithMediaTypes("text/plain");
        ApiResponse response2 = mockResponseWithMediaTypes("text/plain", "text/plain");
        Operation operation = mockOperationWithResponses(response1, response2);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateAcceptHeaders(operation, headers);
        // Then
        assertThat(headers, contains(header("Accept", "text/plain")));
    }

    @Test
    void shouldNotGenerateHeadersFromParametersIfNonePresent() {
        // Given
        List<Parameter> parameters = null;
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(headers, is(empty()));
    }

    @Test
    void shouldNotGenerateHeadersFromNullParameter() {
        // Given
        List<Parameter> parameters = asList((Parameter) null);
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(headers, is(empty()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"query", "path"})
    void shouldNotGenerateHeadersFromNonHeaderParameter(String in) {
        // Given
        List<Parameter> parameters = asList(param(in, "name"));
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(headers, is(empty()));
    }

    @Test
    void shouldGenerateHeaderFromHeaderParameter() {
        // Given
        String headerName = "HeaderName";
        String headerValue = "HeaderValue";
        Parameter headerParameter = headerParam(headerName);
        given(dataGenerator.generate(headerName, headerParameter)).willReturn(headerValue);
        List<Parameter> parameters = asList(headerParameter);
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(headers, contains(header(headerName, headerValue)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldGenerateHeadersFromHeadersParameters() {
        // Given
        String headerName1 = "HeaderName1";
        String headerValue1 = "HeaderValue1";
        Parameter headerParameter1 = headerParam(headerName1);
        given(dataGenerator.generate(headerName1, headerParameter1)).willReturn(headerValue1);
        String headerName2 = "HeaderName2";
        String headerValue2 = "HeaderValue2";
        Parameter headerParameter2 = headerParam(headerName2);
        given(dataGenerator.generate(headerName2, headerParameter2)).willReturn(headerValue2);
        List<Parameter> parameters = asList(headerParameter1, headerParameter2);
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(
                headers,
                contains(header(headerName1, headerValue1), header(headerName2, headerValue2)));
    }

    @Test
    void shouldGenerateCookieHeaderFromCookieParameter() {
        // Given
        String cookieName = "CookieName";
        String cookieValue = "CookieValue";
        Parameter cookieParameter = cookieParam(cookieName);
        given(dataGenerator.generate(cookieName, cookieParameter)).willReturn(cookieValue);
        List<Parameter> parameters = asList(cookieParameter);
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(headers, contains(header("Cookie", cookieName + "=" + cookieValue)));
    }

    @Test
    void shouldGenerateSingleCookieHeaderFromCookieParameters() {
        // Given
        String cookieName1 = "CookieName1";
        String cookieValue1 = "CookieValue1";
        Parameter cookieParameter1 = cookieParam(cookieName1);
        given(dataGenerator.generate(cookieName1, cookieParameter1)).willReturn(cookieValue1);
        String cookieName2 = "CookieName2";
        String cookieValue2 = "CookieValue2";
        Parameter cookieParameter2 = cookieParam(cookieName2);
        given(dataGenerator.generate(cookieName2, cookieParameter2)).willReturn(cookieValue2);
        List<Parameter> parameters = asList(cookieParameter1, cookieParameter2);
        Operation operation = mockOperationWithParameters(parameters);
        List<HttpHeaderField> headers = new ArrayList<>();
        // When
        headersGenerator.generateCustomHeader(operation, headers);
        // Then
        assertThat(
                headers,
                contains(
                        header(
                                "Cookie",
                                cookieName1
                                        + "="
                                        + cookieValue1
                                        + "; "
                                        + cookieName2
                                        + "="
                                        + cookieValue2)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldGenerateAllSupportedHeaders() {
        // Given
        Operation operation = mock(Operation.class);

        ApiResponse response = mockResponseWithMediaTypes("text/plain");
        mockOperationWithResponses(operation, response);

        RequestBody request = mockRequestWithMediaTypes("application/json");
        mockOperationWithRequest(operation, request);

        String headerName = "HeaderName";
        String headerValue = "HeaderValue";
        Parameter headerParameter = headerParam(headerName);
        given(dataGenerator.generate(headerName, headerParameter)).willReturn(headerValue);

        String cookieName = "CookieName1";
        String cookieValue = "CookieValue1";
        Parameter cookieParameter = cookieParam(cookieName);
        given(dataGenerator.generate(cookieName, cookieParameter)).willReturn(cookieValue);

        List<Parameter> parameters = asList(headerParameter, cookieParameter);
        mockOperationWithParameters(operation, parameters);

        OperationModel operationModel = mock(OperationModel.class);
        given(operationModel.getOperation()).willReturn(operation);
        // When
        List<HttpHeaderField> headers = headersGenerator.generate(operationModel);
        // Then
        assertThat(
                headers,
                contains(
                        header("Accept", "text/plain"),
                        header("Content-Type", "application/json"),
                        header(headerName, headerValue),
                        header("Cookie", cookieName + "=" + cookieValue)));
    }

    private static ApiResponse mockResponseWithMediaTypes(String... types) {
        ApiResponse response = mock(ApiResponse.class);
        if (types != null) {
            Content content = mockContentWithMediaType(types);
            given(response.getContent()).willReturn(content);
        }
        return response;
    }

    private static Operation mockOperationWithResponses(ApiResponse... apiResponses) {
        Operation operation = mock(Operation.class);
        mockOperationWithResponses(operation, apiResponses);
        return operation;
    }

    private static void mockOperationWithResponses(
            Operation operation, ApiResponse... apiResponses) {
        ApiResponses responses = mock(ApiResponses.class);
        given(responses.values()).willReturn(asList(apiResponses));
        given(operation.getResponses()).willReturn(responses);
    }

    private static Parameter headerParam(String name) {
        return param("header", name);
    }

    private static Parameter cookieParam(String name) {
        return param("cookie", name);
    }

    private static Parameter param(String in, String name) {
        Parameter parameter = mock(Parameter.class);
        given(parameter.getIn()).willReturn(in);
        given(parameter.getName()).willReturn(name);
        return parameter;
    }

    private static Operation mockOperationWithParameters(List<Parameter> parameters) {
        Operation operation = mock(Operation.class);
        mockOperationWithParameters(operation, parameters);
        return operation;
    }

    private static void mockOperationWithParameters(
            Operation operation, List<Parameter> parameters) {
        given(operation.getParameters()).willReturn(parameters);
    }

    private static RequestBody mockRequestWithMediaTypes(String... types) {
        RequestBody request = mock(RequestBody.class);
        if (types != null) {
            Content content = mockContentWithMediaType(types);
            given(request.getContent()).willReturn(content);
        }
        return request;
    }

    private static Operation mockOperationWithRequest(RequestBody requestBody) {
        Operation operation = mock(Operation.class);
        mockOperationWithRequest(operation, requestBody);
        return operation;
    }

    private static void mockOperationWithRequest(Operation operation, RequestBody requestBody) {
        given(operation.getRequestBody()).willReturn(requestBody);
    }

    private static Content mockContentWithMediaType(String... types) {
        Content content = mock(Content.class);
        given(content.keySet()).willReturn(setOf(types));
        return content;
    }

    @SafeVarargs
    @SuppressWarnings("varargs")
    private static <T> Set<T> setOf(T... values) {
        Set<T> set = new LinkedHashSet<>();
        Collections.addAll(set, values);
        return set;
    }

    private static Matcher<HttpHeaderField> header(String name) {
        return new BaseMatcher<HttpHeaderField>() {

            @Override
            public boolean matches(Object actualValue) {
                HttpHeaderField header = (HttpHeaderField) actualValue;
                return name.equals(header.getName());
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("header ").appendValue(name);
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                HttpHeaderField header = (HttpHeaderField) item;
                description
                        .appendText("was ")
                        .appendValue(header.getName() + ": " + header.getValue());
            }
        };
    }

    private static Matcher<HttpHeaderField> header(String name, String value) {
        return new BaseMatcher<HttpHeaderField>() {

            @Override
            public boolean matches(Object actualValue) {
                HttpHeaderField header = (HttpHeaderField) actualValue;
                return name.equals(header.getName()) && value.equals(header.getValue());
            }

            @Override
            public void describeTo(Description description) {
                description.appendText("header ").appendValue(name + ": " + value);
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                HttpHeaderField header = (HttpHeaderField) item;
                description
                        .appendText("was ")
                        .appendValue(header.getName() + ": " + header.getValue());
            }
        };
    }
}
