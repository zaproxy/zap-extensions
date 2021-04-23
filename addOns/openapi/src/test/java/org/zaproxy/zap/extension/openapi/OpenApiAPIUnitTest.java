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
package org.zaproxy.zap.extension.openapi;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.model.DefaultNameValuePair;
import org.zaproxy.zap.model.NameValuePair;

/** Unit test for {@link OpenApiAPI}. */
public class OpenApiAPIUnitTest extends AbstractServerTest {

    private ExtensionOpenApi extension;

    private OpenApiAPI openApiAPI;

    @BeforeEach
    public void prepare() {
        extension = mock(ExtensionOpenApi.class);
        openApiAPI = new OpenApiAPI(extension);
    }

    @Test
    public void shouldThrowBadActionIfActionUnknown() {
        // Given
        String actionName = "_NotKnownAction_";
        // When / Then
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> openApiAPI.handleApiAction(actionName, params()));
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @Nested
    class ApiImportUrl {

        @Test
        public void shouldThrowIllegalParameterIfErrorDetected() {
            // Given
            String fakeError = "fakeError";
            JSONObject params =
                    params(param(OpenApiAPI.PARAM_URL, "http://not-reachable.example.com"));
            given(extension.importOpenApiDefinition(any(URI.class), eq(""), eq(false)))
                    .willReturn(Collections.singletonList(fakeError));
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(OpenApiAPI.ACTION_IMPORT_URL, params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
            assertThat(exception.toString(), containsString(fakeError));
        }

        @Test
        public void shouldImportWithNoErrorDetected() throws ApiException {
            // Given
            JSONObject params =
                    params(param(OpenApiAPI.PARAM_URL, "http://not-reachable.example.com"));
            given(extension.importOpenApiDefinition(any(URI.class), eq(""), eq(false)))
                    .willReturn(null);
            // When
            ApiResponse apiResponse =
                    openApiAPI.handleApiAction(OpenApiAPI.ACTION_IMPORT_URL, params);

            // Then
            assertThat(
                    "Import URL Action returned",
                    apiResponse.getName().equals(OpenApiAPI.ACTION_IMPORT_URL));
        }
    }

    @Nested
    class ApiImportFile {
        @Test
        public void shouldThrowFileDoesntExist() {
            // Given
            String fileName = "non-existent.json";
            JSONObject params = params(param(OpenApiAPI.PARAM_FILE, fileName));

            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () ->
                                    openApiAPI.handleApiAction(
                                            OpenApiAPI.ACTION_IMPORT_FILE, params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.DOES_NOT_EXIST)));
            assertThat(exception.toString(), containsString(fileName));
        }

        @Test
        public void shouldThrowIllegalParamIfNotAFile() {
            // Given
            String directory = "v1";
            JSONObject params = params(param(OpenApiAPI.PARAM_FILE, getResourceAsFile(directory)));

            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () ->
                                    openApiAPI.handleApiAction(
                                            OpenApiAPI.ACTION_IMPORT_FILE, params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
            assertThat(exception.toString(), containsString(directory));
        }

        @Test
        public void shouldThrowIllegalParameterIfErrorDetected() {
            // Given
            String parseError = "parseError";
            JSONObject params =
                    params(param(OpenApiAPI.PARAM_FILE, getResourceAsFile("bad-json.json")));
            given(extension.importOpenApiDefinition(any(File.class), eq(""), eq(false)))
                    .willReturn(Collections.singletonList(parseError));
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () ->
                                    openApiAPI.handleApiAction(
                                            OpenApiAPI.ACTION_IMPORT_FILE, params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
            assertThat(exception.toString(), containsString(parseError));
        }

        @Test
        public void shouldImportWithNoErrorDetected() throws ApiException {
            // Given
            JSONObject params =
                    params(param(OpenApiAPI.PARAM_FILE, getResourceAsFile("bad-json.json")));
            given(extension.importOpenApiDefinition(any(File.class), eq(""), eq(false)))
                    .willReturn(null);
            // When
            ApiResponse apiResponse =
                    openApiAPI.handleApiAction(OpenApiAPI.ACTION_IMPORT_FILE, params);

            // Then
            assertThat(
                    "Import File Action Returned",
                    apiResponse.getName().equals(OpenApiAPI.ACTION_IMPORT_FILE));
        }
    }

    private String getResourceAsFile(String file) {
        return getClass().getResource(file).getFile();
    }

    private static JSONObject params(NameValuePair... params) {
        if (params == null || params.length == 0) {
            return JSONObject.fromObject(new HashMap<>());
        }

        return JSONObject.fromObject(
                Arrays.stream(params)
                        .collect(
                                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue)));
    }

    private static NameValuePair param(String name, String value) {
        return new DefaultNameValuePair(name, value);
    }
}
