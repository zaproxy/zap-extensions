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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.servers.ServerVariable;
import io.swagger.v3.oas.models.servers.ServerVariables;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.openapi.AbstractOpenApiTest;
import org.zaproxy.zap.extension.openapi.network.RequestModel;

/** Unit test for {@link SwaggerConverter}. */
class SwaggerConverterUnitTest extends AbstractOpenApiTest {

    private static final String WELLFORMED_URL = "http://example.com";
    private static final String DUMMY_DEFINITION = "{}";
    private static final UriBuilder EMPTY_URI_BUILDER = UriBuilder.parse("");

    @Test
    void shouldThrowInvalidUrlIfDefinitionUrlHasNoScheme() {
        // Given
        String definitionUrl = "://example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfDefinitionUrlHasNoAuthority() {
        // Given
        String definitionUrl = "http://";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfDefinitionUrlHasMalformedScheme() {
        // Given
        String definitionUrl = "notscheme//example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfDefinitionUrlIsJustPath() {
        // Given
        String definitionUrl = "path";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfDefinitionUrlIsNull() {
        // Given
        String definitionUrl = null;
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfDefinitionUrlIsEmpty() {
        // Given
        String definitionUrl = "";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfDefinitionUrlHasHttpSchemeAndAuthority() {
        // Given
        String definitionUrl = "http://example.com";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfDefinitionUrlHasHttpsSchemeAndAuthority() {
        // Given
        String definitionUrl = "https://example.com";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfDefinitionUrlHasUnsupportedScheme() {
        // Given
        String definitionUrl = "ws://example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfDefinitionUrlHasSupportedSchemeAuthorityAndPath() {
        // Given
        String definitionUrl = "http://example.com/path";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfTargetUrlHasNoScheme() {
        // Given
        String targetUrl = "://example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetIsJustHttpScheme() {
        // Given
        String targetUrl = "http://";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetIsJustHttpsScheme() {
        // Given
        String targetUrl = "https://";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfTargetUrlHasMalformedScheme() {
        // Given
        String targetUrl = "notscheme//example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlIsJustAuthority() {
        // Given
        String targetUrl = "example.com";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlIsJustAbsolutePath() {
        // Given
        String targetUrl = "/path";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlIsNull() {
        // Given
        String targetUrl = null;
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlIsEmpty() {
        // Given
        String targetUrl = "";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlHasHttpSchemeAndAuthority() {
        // Given
        String targetUrl = "http://example.com";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlHasHttpsSchemeAndAuthority() {
        // Given
        String targetUrl = "https://example.com";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowInvalidUrlIfTargetUrlHasUnsupportedScheme() {
        // Given
        String targetUrl = "ws://example.com";
        // When / Then
        assertThrows(
                InvalidUrlException.class,
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldNotThrowInvalidUrlIfTargetUrlHasSupportedSchemeAuthorityAndPath() {
        // Given
        String targetUrl = "http://example.com/path";
        // When / Then
        assertDoesNotThrow(
                () -> new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null));
    }

    @Test
    void shouldThrowIllegalArgumentWith2ArgIfDefinitionIsNull() {
        // Given
        String definition = null;
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> new SwaggerConverter(definition, null));
    }

    @Test
    void shouldThrowIllegalArgumentWith4ArgIfDefinitionIsNull() {
        // Given
        String definition = null;
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> new SwaggerConverter(null, null, definition, null));
    }

    @Test
    void shouldThrowIllegalArgumentWith2ArgIfDefinitionIsEmpty() {
        // Given
        String definition = "";
        // When / Then
        assertThrows(IllegalArgumentException.class, () -> new SwaggerConverter(definition, null));
    }

    @Test
    void shouldThrowIllegalArgumentWith4ArgIfDefinitionIsEmpty() {
        // Given
        String definition = "";
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> new SwaggerConverter(null, null, definition, null));
    }

    @Test
    void shouldCreateSwaggerConverter2ArgWithDefinitionNotEmpty() {
        // Given
        String definition = "{}";
        // When / Then
        assertDoesNotThrow(() -> new SwaggerConverter(definition, null));
    }

    @Test
    void shouldCreateSwaggerConverter4ArgWithDefinitionNotEmpty() {
        // Given
        String definition = "{}";
        // When / Then
        assertDoesNotThrow(() -> new SwaggerConverter(null, null, definition, null));
    }

    @Test
    void shouldThrowNullPointerWhenCreateUriBuildersFromNullServersList() {
        // Given
        List<Server> servers = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER));
    }

    @Test
    void shouldCreateEmptyUriBuilderListFromEmptyServerList() {
        // Given
        List<Server> servers = Collections.emptyList();
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, is(empty()));
    }

    @Test
    void shouldCreateUriBuildersFromServerWithEmptyValue() {
        // Given
        List<Server> servers = asList(server(""));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), null, null, null);
    }

    @Test
    void shouldCreateUriBuildersFromServerWithEmptyValueDefaultingToDefinitionUrl() {
        // Given
        List<Server> servers = asList(server(""));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/path");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithJustRelativePath() {
        // Given
        List<Server> servers = asList(server("relativePath"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), null, null, "relativePath");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithJustRelativePathDefaultingToSchemeAndAuthorityOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("relativePath"));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "relativePath");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithJustRelativePathDefaultingToSchemeAndAuthorityAndMergingPathOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("relativePath"));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/path/relativePath");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithAbsolutePath() {
        // Given
        List<Server> servers = asList(server("/absolutePath"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), null, null, "/absolutePath");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithAbsolutePathDefaultingToSchemeAndAuthorityOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("/absolutePath"));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/absolutePath");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithAuthorityAndNoScheme() {
        // Given
        List<Server> servers = asList(server("//example.com"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), null, "example.com", "");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithAuthorityAndNoSchemeDefaultingToSchemeOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("//example.com"));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithEmptyAuthority() {
        // Given
        List<Server> servers = asList(server("//"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), null, null, null);
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithEmptyAuthorityDefaultingToSchemeAuthorityAndPathOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("//"));
        UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/path");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithScheme() {
        // Given
        List<Server> servers = asList(server("http://"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", null, "");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithSchemeDefaultingToAuthorityAndPathOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("http://"));
        UriBuilder defnUriBuilder = UriBuilder.parse("https://example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithSchemeAndAuthority() {
        // Given
        List<Server> servers = asList(server("http://example.com"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithSchemeAndAuthorityDefaultingToAuthorityAndPathOfDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("http://example.com"));
        UriBuilder defnUriBuilder = UriBuilder.parse("https://other.example.com/path");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithSchemeAuthorityAndEmptyPath() {
        // Given
        List<Server> servers = asList(server("http://example.com/"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithSchemeAuthorityAndEmptyPathWithoutDefaultingToDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("http://example.com/"));
        UriBuilder defnUriBuilder = UriBuilder.parse("https://other.example.com/defnpath");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithSchemeAuthorityAndNonEmptyPath() {
        // Given
        List<Server> servers = asList(server("http://example.com/path"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/path");
    }

    @Test
    void
            shouldCreateUriBuildersFromServerWithSchemeAuthorityAndNonEmptyPathWithoutDefaultingToDefinitionUrl() {
        // Given
        List<Server> servers = asList(server("http://example.com/path"));
        UriBuilder defnUriBuilder = UriBuilder.parse("https://other.example.com/defnpath");
        // When
        List<UriBuilder> uriBuilders = SwaggerConverter.createUriBuilders(servers, defnUriBuilder);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/path");
    }

    @Test
    void shouldCreateUriBuildersFromMultipleServers() {
        // Given
        List<Server> servers =
                asList(server("http://dev.example.com/api/"), server("https://qa.example.com/v2"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(2));
        assertUriBuilder(uriBuilders.get(0), "http", "dev.example.com", "/api/");
        assertUriBuilder(uriBuilders.get(1), "https", "qa.example.com", "/v2");
    }

    @Test
    void shouldCreateUriBuildersFromServerWithVariables() {
        // Given
        Server server = server("{scheme}://example.com/");
        ServerVariables variables = new ServerVariables();
        variables.put("scheme", new ServerVariable()._default("http"));
        server.setVariables(variables);
        List<Server> servers = asList(server);
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(1));
        assertUriBuilder(uriBuilders.get(0), "http", "example.com", "/");
    }

    @Test
    void shouldIgnoreServersWithUnsupportedScheme() {
        // Given
        List<Server> servers =
                asList(server("ws://dev.example.com/api/"), server("wss://qa.example.com/v2"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(0));
    }

    @Test
    void shouldIgnoreServersWithEmptyScheme() {
        // Given
        List<Server> servers = asList(server("://"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(0));
    }

    @Test
    void shouldIgnoreServersWithMalformedScheme() {
        // Given
        List<Server> servers = asList(server("notscheme//"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(0));
    }

    @Test
    void shouldCreateApiUrlJustFromServerUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(UriBuilder.parse("http://example.com/serverpath"));
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://example.com/serverpath"));
    }

    @Test
    void shouldCreateApiUrlsFromMultipleServerUrls() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(
                        UriBuilder.parse("http://qa.example.com/"),
                        UriBuilder.parse("http://dev.example.com/"));
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        // Then
        assertThat(
                serverUrls, containsInAnyOrder("http://qa.example.com", "http://dev.example.com"));
    }

    @Test
    void shouldIgnoreDuplicatedServerUrls() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(
                        UriBuilder.parse("http://qa.example.com/"),
                        UriBuilder.parse("http://qa.example.com/"));
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://qa.example.com"));
    }

    @Test
    void shouldFailToCreateApiUrlIfNoServerUrl() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldFailToCreateApiUrlFromEmptyServerUrl() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse(""));
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldFailToCreateApiUrlFromJustServerUrlWithoutScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("//example.com"));
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldFailToCreateApiUrlFromJustServerUrlWithoutAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://"));
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldFailToCreateApiUrlFromMalformedServerUrl() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://x%0"));
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldFailToCreateApiUrlFromMalformedServerUrlWithNonEmptyDefinitionUrl() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("//x%0"));
            UriBuilder defnUriBuilder = UriBuilder.parse("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, EMPTY_URI_BUILDER, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("any server URL"));
        }
    }

    @Test
    void shouldCreateApiUrlJustFromTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders = asList();
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://example.com");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://example.com"));
    }

    @Test
    void shouldFailToCreateApiUrlJustFromTargetUrlIfMalformed() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://x%0");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlIsMalformed() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse(""));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://x%0");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlIsMalformed() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://example.com"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://x%0");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlIsMalformed() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://x%0");
            UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlIsMalformed() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://example.com"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://x%0");
            UriBuilder defnUriBuilder = UriBuilder.parse("http://example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldCreateApiUrlWithSchemeFromTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://example.com"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("https://example.com");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("https://example.com"));
    }

    @Test
    void shouldCreateApiUrlWithSchemeFromServerUrlIfNotInTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("https://example.com"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("https://example.com"));
    }

    @Test
    void shouldFailToCreateApiUrlJustFromTargetUrlIfHasNoScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("scheme"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlHasNoScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse(""));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("scheme"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlHasNoScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("//example.com"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("scheme"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlHasNoScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
            UriBuilder defnUriBuilder = UriBuilder.parse("//example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("scheme"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlHasNoScheme() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("//example.com"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("//example.com");
            UriBuilder defnUriBuilder = UriBuilder.parse("//example.com");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("scheme"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldCreateApiUrlWithAuthorityFromTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://server.example.com"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://target.example.com");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://target.example.com"));
    }

    @Test
    void shouldCreateApiUrlWithAuthorityFromServerUrlIfNotInTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://server.example.com"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://server.example.com"));
    }

    @Test
    void shouldFailToCreateApiUrlJustFromTargetUrlIfHasNoAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("authority"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlHasNoAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse(""));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("authority"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlHasNoAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("authority"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), not(containsString("Definition URL: ")));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlHasNoAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList();
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
            UriBuilder defnUriBuilder = UriBuilder.parse("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("authority"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), not(containsString("Server URL: ")));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlHasNoAuthority() {
        try {
            // Given
            List<UriBuilder> serverUriBuilders = asList(UriBuilder.parse("http://"));
            UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://");
            UriBuilder defnUriBuilder = UriBuilder.parse("http://");
            // When
            SwaggerConverter.createApiUrls(serverUriBuilders, targetUriBuilder, defnUriBuilder);
        } catch (SwaggerException e) {
            // Then
            assertThat(e.getMessage(), containsString("authority"));
            assertThat(e.getMessage(), containsString("target URL"));
            assertThat(e.getMessage(), containsString("Server URL: "));
            assertThat(e.getMessage(), containsString("Definition URL: "));
        }
    }

    @Test
    void shouldCreateApiUrlWithPathFromTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(UriBuilder.parse("http://example.com/serverpath/"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://example.com/targetpath/");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://example.com/targetpath"));
    }

    @Test
    void shouldCreateApiUrlWithPathFromTargetUrlEvenIfEmpty() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(UriBuilder.parse("http://example.com/serverpath/"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://example.com/");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://example.com"));
    }

    @Test
    void shouldCreateApiUrlWithPathFromServerUrlIfNotInTargetUrl() throws SwaggerException {
        // Given
        List<UriBuilder> serverUriBuilders =
                asList(UriBuilder.parse("http://example.com/serverpath/"));
        UriBuilder targetUriBuilder = UriBuilder.parseLenient("http://example.com");
        // When
        Set<String> serverUrls =
                SwaggerConverter.createApiUrls(
                        serverUriBuilders, targetUriBuilder, EMPTY_URI_BUILDER);
        // Then
        assertThat(serverUrls, contains("http://example.com/serverpath"));
    }

    @Test
    void shouldUsePathServers() throws Exception {
        // Given
        String definition = getHtml("openapi_path_servers.yaml");
        SwaggerConverter converter = new SwaggerConverter(definition, null);
        // When
        List<RequestModel> requests = converter.getRequestModels();
        // Then
        assertThat(converter.getErrorMessages(), is(empty()));
        assertThat(
                urlsOf(requests),
                contains(
                        "http://server0.localhost/path/without/servers",
                        "http://server1.localhost/path/with/server",
                        "http://server2.localhost/v1/path/with/servers",
                        "http://server3.localhost/path/with/servers"));
    }

    @Test
    void shouldUseTargetUrlForPathServers() throws Exception {
        // Given
        String definition = getHtml("openapi_path_servers.yaml");
        SwaggerConverter converter =
                new SwaggerConverter("/v2/", "http://localhost/definition/", definition, null);
        // When
        List<RequestModel> requests = converter.getRequestModels();
        // Then
        assertThat(converter.getErrorMessages(), is(empty()));
        assertThat(
                urlsOf(requests),
                contains(
                        "http://server0.localhost/v2/path/without/servers",
                        "http://server1.localhost/v2/path/with/server",
                        "http://server2.localhost/v2/path/with/servers"));
    }

    @Test
    void shouldUseOperationServers() throws Exception {
        // Given
        String definition = getHtml("openapi_operation_servers.yaml");
        SwaggerConverter converter = new SwaggerConverter(definition, null);
        // When
        List<RequestModel> requests = converter.getRequestModels();
        // Then
        assertThat(converter.getErrorMessages(), is(empty()));
        assertThat(
                methodsAndUrlsOf(requests),
                contains(
                        "GET http://server0.localhost/operation/without/servers",
                        "GET http://server1.localhost/operations/with/servers",
                        "POST http://server2.localhost/v1/operations/with/servers",
                        "POST http://server3.localhost/operations/with/servers",
                        "PUT http://server4.localhost/operations/with/servers",
                        "HEAD http://server5.localhost/operations/with/servers",
                        "OPTIONS http://server6.localhost/operations/with/servers",
                        "DELETE http://server7.localhost/operations/with/servers",
                        "PATCH http://server8.localhost/operations/with/servers"));
    }

    @Test
    void shouldUseTargetUrlForOperationServers() throws Exception {
        // Given
        String definition = getHtml("openapi_operation_servers.yaml");
        SwaggerConverter converter =
                new SwaggerConverter("/v2/", "http://localhost/definition/", definition, null);
        // When
        List<RequestModel> requests = converter.getRequestModels();
        // Then
        assertThat(converter.getErrorMessages(), is(empty()));
        assertThat(
                methodsAndUrlsOf(requests),
                contains(
                        "GET http://server0.localhost/v2/operation/without/servers",
                        "GET http://server1.localhost/v2/operations/with/servers",
                        "POST http://server2.localhost/v2/operations/with/servers",
                        "PUT http://server4.localhost/v2/operations/with/servers",
                        "HEAD http://server5.localhost/v2/operations/with/servers",
                        "OPTIONS http://server6.localhost/v2/operations/with/servers",
                        "DELETE http://server7.localhost/v2/operations/with/servers",
                        "PATCH http://server8.localhost/v2/operations/with/servers"));
    }

    private static List<String> urlsOf(List<RequestModel> requests) {
        return requests.stream().map(RequestModel::getUrl).collect(Collectors.toList());
    }

    private static List<String> methodsAndUrlsOf(List<RequestModel> requests) {
        return requests.stream()
                .map(e -> e.getMethod() + " " + e.getUrl())
                .collect(Collectors.toList());
    }

    private static void assertUriBuilder(
            UriBuilder uriBuilder, String scheme, String host, String path) {
        assertThat(uriBuilder.getScheme(), is(equalTo(scheme)));
        assertThat(uriBuilder.getAuthority(), is(equalTo(host)));
        assertThat(uriBuilder.getPath(), equalTo(path));
    }

    private static Server server(String url) {
        Server server = new Server();
        server.setUrl(url);
        return server;
    }
}
