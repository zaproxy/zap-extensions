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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.API.RequestType;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiParameter;
import org.zaproxy.zap.extension.users.ContextUserAuthManager;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.DefaultNameValuePair;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.users.User;

/** Unit test for {@link OpenApiAPI}. */
class OpenApiAPIUnitTest extends AbstractServerTest {

    private Session session;
    private Model model;
    private ExtensionLoader extensionLoader;
    private ExtensionUserManagement extensionUserManagement;
    private ExtensionOpenApi extension;

    private OpenApiAPI openApiAPI;

    @BeforeEach
    void prepare() {
        session = mock(Session.class);
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        extension = mock(ExtensionOpenApi.class, withSettings().strictness(Strictness.LENIENT));
        given(extension.getModel()).willReturn(model);

        extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(model, extensionLoader);

        openApiAPI = new OpenApiAPI(extension);
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownAction(String name) throws Exception {
        // Given
        JSONObject params = params();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> openApiAPI.handleApiAction(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_ACTION)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownView(String name) throws Exception {
        // Given
        JSONObject params = params();
        // When
        ApiException exception =
                assertThrows(ApiException.class, () -> openApiAPI.handleApiView(name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_VIEW)));
    }

    @ParameterizedTest
    @EmptySource
    @ValueSource(strings = {"unknown", "something"})
    void shouldThrowApiExceptionForUnknownOther(String name) throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        JSONObject params = params();
        // When
        ApiException exception =
                assertThrows(
                        ApiException.class, () -> openApiAPI.handleApiOther(message, name, params));
        // Then
        assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_OTHER)));
    }

    @Test
    void shouldHaveDescriptionsForAllApiElements() {
        openApiAPI = new OpenApiAPI(extension);
        List<String> missingKeys = new ArrayList<>();
        checkKey(openApiAPI.getDescriptionKey(), missingKeys);
        checkApiElements(
                openApiAPI, openApiAPI.getApiActions(), API.RequestType.action, missingKeys);
        checkApiElements(openApiAPI, openApiAPI.getApiOthers(), API.RequestType.other, missingKeys);
        checkApiElements(openApiAPI, openApiAPI.getApiViews(), API.RequestType.view, missingKeys);
        assertThat(missingKeys, is(empty()));
    }

    private static void checkKey(String key, List<String> missingKeys) {
        if (!Constant.messages.containsKey(key)) {
            missingKeys.add(key);
        }
    }

    private static void checkApiElements(
            ApiImplementor api,
            List<? extends ApiElement> elements,
            RequestType type,
            List<String> missingKeys) {
        elements.sort((a, b) -> a.getName().compareTo(b.getName()));
        for (ApiElement element : elements) {
            assertThat(
                    "API " + type + " element: " + api.getPrefix() + "/" + element.getName(),
                    element.getDescriptionTag(),
                    is(not(emptyString())));
            checkKey(element.getDescriptionTag(), missingKeys);
            element.getParameters().stream()
                    .map(ApiParameter::getDescriptionKey)
                    .forEach(key -> checkKey(key, missingKeys));
        }
    }

    private abstract class BaseImportTests {

        abstract String getAction();

        abstract NameValuePair getImportParam();

        @Test
        void shouldThrowApiExceptionIfUserProvidedButNoContextExists() {
            // Given
            JSONObject params = params(getImportParam(), param("userId", "1"));
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(getAction(), params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.MISSING_PARAMETER)));
            assertThat(exception.toString(), containsString("(missing_parameter): contextId"));
        }

        @Test
        void shouldThrowApiExceptionIfUserExtensionNotEnabled() {
            // Given
            JSONObject params = params(getImportParam(), param("userId", "1"));
            defaultContext();
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(getAction(), params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.NO_IMPLEMENTOR)));
            assertThat(
                    exception.toString(),
                    containsString("(no_implementor): ExtensionUserManagement"));
        }

        @Test
        void shouldThrowApiExceptionIfUserNotFound() {
            // Given
            JSONObject params = params(getImportParam(), param("userId", "1"));
            userExtensionEnabled();
            defaultContext();
            userIdsDefaultContext(2);
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(getAction(), params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.USER_NOT_FOUND)));
            assertThat(exception.toString(), containsString("(user_not_found): userId"));
        }
    }

    @Nested
    class ApiImportFile extends BaseImportTests {

        private static final String ACTION = "importFile";

        private File importFile;

        @Override
        String getAction() {
            return ACTION;
        }

        @Override
        NameValuePair getImportParam() {
            try {
                importFile = Files.createTempFile("openapi", "").toFile();
                return param("file", importFile.getAbsolutePath());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Test
        void shouldUseProvidedUser() throws Exception {
            // Given
            JSONObject params = params(getImportParam(), param("userId", "1"));
            userExtensionEnabled();
            defaultContext();
            userIdsDefaultContext(1);
            given(
                            extension.importOpenApiDefinition(
                                    any(File.class),
                                    any(String.class),
                                    anyBoolean(),
                                    anyInt(),
                                    any(User.class)))
                    .willReturn(List.of());
            // When
            openApiAPI.handleApiAction(ACTION, params);
            // Then
            verify(extension)
                    .importOpenApiDefinition(
                            importFile,
                            "",
                            false,
                            1,
                            extensionUserManagement.getContextUserAuthManager(1).getUserById(1));
        }

        @Test
        void shouldThrowApiExceptionIfUnableToParseFile() {
            // Given
            JSONObject params = params(getImportParam());
            given(
                            extension.importOpenApiDefinition(
                                    any(File.class), eq(""), eq(false), eq(-1), eq(null)))
                    .willReturn(null);
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(getAction(), params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.BAD_EXTERNAL_DATA)));
            assertThat(exception.toString(), containsString("(bad_external_data): file"));
        }
    }

    @Nested
    class ApiImportUrl extends BaseImportTests {

        private static final String ACTION = "importUrl";

        @Override
        String getAction() {
            return ACTION;
        }

        @Override
        NameValuePair getImportParam() {
            return param("url", "http://example.com");
        }

        @Test
        void shouldUseProvidedUser() throws Exception {
            // Given
            JSONObject params = params(getImportParam(), param("userId", "1"));
            userExtensionEnabled();
            defaultContext();
            userIdsDefaultContext(1);
            given(
                            extension.importOpenApiDefinition(
                                    any(URI.class),
                                    any(String.class),
                                    anyBoolean(),
                                    anyInt(),
                                    any(User.class)))
                    .willReturn(List.of());
            // When
            openApiAPI.handleApiAction(ACTION, params);
            // Then
            verify(extension)
                    .importOpenApiDefinition(
                            new URI("http://example.com", true),
                            "",
                            false,
                            1,
                            extensionUserManagement.getContextUserAuthManager(1).getUserById(1));
        }

        @Test
        void shouldThrowIllegalParameterIfFailedToAccessTarget() {
            // Given
            JSONObject params = params(getImportParam());
            given(
                            extension.importOpenApiDefinition(
                                    any(URI.class), eq(""), eq(false), eq(-1), eq(null)))
                    .willReturn(null);
            // When / Then
            ApiException exception =
                    assertThrows(
                            ApiException.class,
                            () -> openApiAPI.handleApiAction(getAction(), params));
            assertThat(exception.getType(), is(equalTo(ApiException.Type.ILLEGAL_PARAMETER)));
            assertThat(exception.toString(), containsString("Failed to access the target."));
        }
    }

    private static JSONObject params(NameValuePair... params) {
        if (params == null || params.length == 0) {
            return JSONObject.fromObject(new HashMap<>());
        }

        return JSONObject.fromObject(
                Arrays.asList(params).stream()
                        .collect(
                                Collectors.toMap(NameValuePair::getName, NameValuePair::getValue)));
    }

    void userExtensionEnabled() {
        extensionUserManagement = mock(ExtensionUserManagement.class);
        given(extensionLoader.getExtension(ExtensionUserManagement.class))
                .willReturn(extensionUserManagement);
    }

    void defaultContext() {
        var context = mock(Context.class);
        given(context.getId()).willReturn(1);
        given(session.getContexts()).willReturn(List.of(context));
    }

    void userIdsDefaultContext(int... ids) {
        var userAuthManager =
                mock(ContextUserAuthManager.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionUserManagement.getContextUserAuthManager(1)).willReturn(userAuthManager);
        if (ids != null && ids.length != 0) {
            Arrays.stream(ids)
                    .forEach(
                            e ->
                                    given(userAuthManager.getUserById(e))
                                            .willReturn(mock(User.class)));
        }
    }

    private static NameValuePair param(String name, String value) {
        return new DefaultNameValuePair(name, value);
    }
}
