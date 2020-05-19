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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.servers.ServerVariable;
import io.swagger.v3.oas.models.servers.ServerVariables;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.junit.Test;
import org.zaproxy.zap.extension.openapi.AbstractOpenApiTest;

/** Unit test for {@link SwaggerConverter}. */
public class SwaggerConverterUnitTest extends AbstractOpenApiTest {

    private static final String WELLFORMED_URL = "http://example.com";
    private static final String DUMMY_DEFINITION = "{}";
    private static final UriBuilder EMPTY_URI_BUILDER = UriBuilder.parse("");

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfDefinitionUrlHasNoScheme() {
        // Given
        String definitionUrl = "://example.com";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfDefinitionUrlHasNoAuthority() {
        // Given
        String definitionUrl = "http://";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfDefinitionUrlHasMalformedScheme() {
        // Given
        String definitionUrl = "notscheme//example.com";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfDefinitionUrlIsJustPath() {
        // Given
        String definitionUrl = "path";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test
    public void shouldNotThrowInvalidUrlIfDefinitionUrlIsNull() {
        // Given
        String definitionUrl = null;
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfDefinitionUrlIsEmpty() {
        // Given
        String definitionUrl = "";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfDefinitionUrlHasHttpSchemeAndAuthority() {
        // Given
        String definitionUrl = "http://example.com";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfDefinitionUrlHasHttpsSchemeAndAuthority() {
        // Given
        String definitionUrl = "https://example.com";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfDefinitionUrlHasUnsupportedScheme() {
        // Given
        String definitionUrl = "ws://example.com";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test
    public void shouldNotThrowInvalidUrlIfDefinitionUrlHasSupportedSchemeAuthorityAndPath() {
        // Given
        String definitionUrl = "http://example.com/path";
        // When
        new SwaggerConverter(WELLFORMED_URL, definitionUrl, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfTargetUrlHasNoScheme() {
        // Given
        String targetUrl = "://example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetIsJustHttpScheme() {
        // Given
        String targetUrl = "http://";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No Exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetIsJustHttpsScheme() {
        // Given
        String targetUrl = "https://";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No Exception
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfTargetUrlHasMalformedScheme() {
        // Given
        String targetUrl = "notscheme//example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlIsJustAuthority() {
        // Given
        String targetUrl = "example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No Exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlIsJustAbsolutePath() {
        // Given
        String targetUrl = "/path";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No Exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlIsNull() {
        // Given
        String targetUrl = null;
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlIsEmpty() {
        // Given
        String targetUrl = "";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlHasHttpSchemeAndAuthority() {
        // Given
        String targetUrl = "http://example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlHasHttpsSchemeAndAuthority() {
        // Given
        String targetUrl = "https://example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test(expected = InvalidUrlException.class)
    public void shouldThrowInvalidUrlIfTargetUrlHasUnsupportedScheme() {
        // Given
        String targetUrl = "ws://example.com";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = InvalidUrlException
    }

    @Test
    public void shouldNotThrowInvalidUrlIfTargetUrlHasSupportedSchemeAuthorityAndPath() {
        // Given
        String targetUrl = "http://example.com/path";
        // When
        new SwaggerConverter(targetUrl, WELLFORMED_URL, DUMMY_DEFINITION, null);
        // Then = No exception
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentWith2ArgIfDefinitionIsNull() {
        // Given
        String definition = null;
        // When
        new SwaggerConverter(definition, null);
        // Then = IllegalArgumentException
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentWith4ArgIfDefinitionIsNull() {
        // Given
        String definition = null;
        // When
        new SwaggerConverter(null, null, definition, null);
        // Then = IllegalArgumentException
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentWith2ArgIfDefinitionIsEmpty() {
        // Given
        String definition = "";
        // When
        new SwaggerConverter(definition, null);
        // Then = IllegalArgumentException
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentWith4ArgIfDefinitionIsEmpty() {
        // Given
        String definition = "";
        // When
        new SwaggerConverter(null, null, definition, null);
        // Then = IllegalArgumentException
    }

    @Test
    public void shouldCreateSwaggerConverter2ArgWithDefinitionNotEmpty() {
        // Given
        String definition = "{}";
        // When
        new SwaggerConverter(definition, null);
        // Then = No Exception
    }

    @Test
    public void shouldCreateSwaggerConverter4ArgWithDefinitionNotEmpty() {
        // Given
        String definition = "{}";
        // When
        new SwaggerConverter(null, null, definition, null);
        // Then = No Exception
    }

    @Test(expected = NullPointerException.class)
    public void shouldThrowNullPointerWhenCreateUriBuildersFromNullServersList() {
        // Given
        List<Server> servers = null;
        // When
        SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then = NullPointerException
    }

    @Test
    public void shouldCreateEmptyUriBuilderListFromEmptyServerList() {
        // Given
        List<Server> servers = Collections.emptyList();
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, is(empty()));
    }

    @Test
    public void shouldCreateUriBuildersFromServerWithEmptyValue() {
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
    public void shouldCreateUriBuildersFromServerWithEmptyValueDefaultingToDefinitionUrl() {
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
    public void shouldCreateUriBuildersFromServerWithJustRelativePath() {
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
    public void
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithAbsolutePath() {
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithAuthorityAndNoScheme() {
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithEmptyAuthority() {
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithScheme() {
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
    public void
            shouldCreateUriBuildersFromServerWithSchemeDefaultingToAuthorityAndPathOfDefinitionUrl() {
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
    public void shouldCreateUriBuildersFromServerWithSchemeAndAuthority() {
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithSchemeAuthorityAndEmptyPath() {
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
    public void
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
    public void shouldCreateUriBuildersFromServerWithSchemeAuthorityAndNonEmptyPath() {
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
    public void
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
    public void shouldCreateUriBuildersFromMultipleServers() {
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
    public void shouldCreateUriBuildersFromServerWithVariables() {
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
    public void shouldIgnoreServersWithUnsupportedScheme() {
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
    public void shouldIgnoreServersWithEmptyScheme() {
        // Given
        List<Server> servers = asList(server("://"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(0));
    }

    @Test
    public void shouldIgnoreServersWithMalformedScheme() {
        // Given
        List<Server> servers = asList(server("notscheme//"));
        // When
        List<UriBuilder> uriBuilders =
                SwaggerConverter.createUriBuilders(servers, EMPTY_URI_BUILDER);
        // Then
        assertThat(uriBuilders, hasSize(0));
    }

    @Test
    public void shouldCreateApiUrlJustFromServerUrl() throws SwaggerException {
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
    public void shouldCreateApiUrlsFromMultipleServerUrls() throws SwaggerException {
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
    public void shouldIgnoreDuplicatedServerUrls() throws SwaggerException {
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
    public void shouldFailToCreateApiUrlIfNoServerUrl() {
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
    public void shouldFailToCreateApiUrlFromEmptyServerUrl() {
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
    public void shouldFailToCreateApiUrlFromJustServerUrlWithoutScheme() {
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
    public void shouldFailToCreateApiUrlFromJustServerUrlWithoutAuthority() {
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
    public void shouldFailToCreateApiUrlFromMalformedServerUrl() {
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
    public void shouldFailToCreateApiUrlFromMalformedServerUrlWithNonEmptyDefinitionUrl() {
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
    public void shouldCreateApiUrlJustFromTargetUrl() throws SwaggerException {
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
    public void shouldFailToCreateApiUrlJustFromTargetUrlIfMalformed() {
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
    public void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlIsMalformed() {
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
    public void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlIsMalformed() {
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
    public void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlIsMalformed() {
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
    public void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlIsMalformed() {
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
    public void shouldCreateApiUrlWithSchemeFromTargetUrl() throws SwaggerException {
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
    public void shouldCreateApiUrlWithSchemeFromServerUrlIfNotInTargetUrl()
            throws SwaggerException {
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
    public void shouldFailToCreateApiUrlJustFromTargetUrlIfHasNoScheme() {
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
    public void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlHasNoScheme() {
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
    public void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlHasNoScheme() {
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
    public void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlHasNoScheme() {
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
    public void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlHasNoScheme() {
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
    public void shouldCreateApiUrlWithAuthorityFromTargetUrl() throws SwaggerException {
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
    public void shouldCreateApiUrlWithAuthorityFromServerUrlIfNotInTargetUrl()
            throws SwaggerException {
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
    public void shouldFailToCreateApiUrlJustFromTargetUrlIfHasNoAuthority() {
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
    public void shouldFailToCreateApiUrlWithEmptyServerUrlIfTargetUrlHasNoAuthority() {
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
    public void shouldFailToCreateApiUrlWithServerUrlIfTargetUrlHasNoAuthority() {
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
    public void shouldFailToCreateApiUrlWithDefinitionUrlIfTargetUrlHasNoAuthority() {
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
    public void shouldFailToCreateApiUrlWithServerUrlDefinitionUrlIfTargetUrlHasNoAuthority() {
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
    public void shouldCreateApiUrlWithPathFromTargetUrl() throws SwaggerException {
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
    public void shouldCreateApiUrlWithPathFromTargetUrlEvenIfEmpty() throws SwaggerException {
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
    public void shouldCreateApiUrlWithPathFromServerUrlIfNotInTargetUrl() throws SwaggerException {
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
