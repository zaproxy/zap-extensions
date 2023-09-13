/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.DefaultValueGenerator;

class VariantOpenApiUnitTest extends AbstractServerTest {

    ExtensionOpenApi extensionOpenApi;

    VariantOpenApi variantOpenApi;

    @BeforeEach
    void setUp() {
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        ExtensionCommonlib extCommonlib =
                mock(ExtensionCommonlib.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionCommonlib.class)).willReturn(extCommonlib);
        given(extCommonlib.getValueGenerator()).willReturn(new DefaultValueGenerator());
        extensionOpenApi = new ExtensionOpenApi();
        extensionOpenApi.initModel(Model.getSingleton());
        Model.getSingleton().closeSession();
        Context context = new Context(Model.getSingleton().getSession(), 0);
        Model.getSingleton().getSession().addContext(context);
        variantOpenApi = new VariantOpenApi(extensionOpenApi);
    }

    @Test
    void shouldGetTreePathWithDdn() throws IOException {
        // Given
        File file = createLocalDefinition("v3/PetStore_defn.json").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        String targetUrl = serverUrl + "/v1";
        // When
        extensionOpenApi.importOpenApiDefinition(file, targetUrl, false, 0);
        // Then
        assertThat(getTreePathAsString("GET", targetUrl + "/pet/1"), is("/v1/pet/«petId»"));
        assertThat(
                getTreePathAsString("GET", targetUrl + "/store/order/2"),
                is("/v1/store/order/«orderId»"));
        assertThat(
                getTreePathAsString("GET", targetUrl + "/user/example"), is("/v1/user/«username»"));
    }

    @Test
    void shouldGetTreePathWithNestedDdns() throws IOException {
        // Given
        File file = createLocalDefinition("v3/MultiVarPath_defn.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/42/subthing/54"),
                is("/api/stuff/«thingid»/subthing/«thingid2»"));
    }

    @Test
    void shouldNotCreateDdnForUrlWithoutPathParamInSpec() throws IOException {
        // Given
        File file = createLocalDefinition("v3/MultiVarPath_defn.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/static"),
                is("/api/stuff/static"));
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/dynamic"),
                is("/api/stuff/«thingid»"));
    }

    @Test
    void shouldCreateDdnsForSpecifiedMethodInSpec() throws IOException {
        // Given
        File file = createLocalDefinition("v3/MultiVarPath_defn.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/42"),
                is("/api/stuff/«thingid»"));
        assertThat(getTreePathAsString("POST", serverUrl + "/api/stuff/42"), is(nullValue()));
    }

    @Test
    void shouldGetTreePathForUriWithQueryParams() throws IOException {
        // Given
        File file = createLocalDefinition("v3/MultiVarPath_defn.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/42/subthing/54?a=b&c=d"),
                is("/api/stuff/«thingid»/subthing/«thingid2»"));
        assertThat(
                getTreePathAsString("GET", serverUrl + "/api/stuff/42/subthing/54/?a=b&c=d"),
                is("/api/stuff/«thingid»/subthing/«thingid2»"));
    }

    @Test
    void shouldCreateSlashNode() throws IOException {
        // Given
        File file = createLocalDefinition("v3/openapi_slash_node.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(getTreePathAsString("GET", serverUrl + "/"), is("/"));
        assertThat(getTreePathAsString("GET", serverUrl + "/?a=b&c=d"), is("/"));
    }

    @Test
    void shouldCreateSlashNodeWithQueryParams() throws IOException {
        // Given
        File file = createLocalDefinition("v3/openapi_slash_node.yaml").toFile();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        // When
        extensionOpenApi.importOpenApiDefinition(file, serverUrl, false, 0);
        // Then
        assertThat(getTreePathAsString("GET", serverUrl), is(""));
        assertThat(getTreePathAsString("GET", serverUrl + "?a=b&c=d"), is(""));
    }

    private Path createLocalDefinition(String path) throws IOException {
        Path directory = Files.createTempDirectory("local-defn");
        Path localDefinition = directory.resolve(path.substring(path.lastIndexOf("/") + 1));
        String fileContents =
                getHtml(
                        path,
                        new String[][] {{"PORT", String.valueOf(this.nano.getListeningPort())}});
        Files.write(localDefinition, fileContents.getBytes(StandardCharsets.UTF_8));
        return localDefinition;
    }

    private String getTreePathAsString(String method, String url) throws IOException {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(method + " " + url + " HTTP/1.1\r\n");
        List<String> treePath = variantOpenApi.getTreePath(msg);
        return treePath != null ? String.join("/", treePath) : null;
    }
}
