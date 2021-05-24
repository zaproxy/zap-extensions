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
package org.zaproxy.zap.extension.openapi;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionOpenApiTest extends AbstractServerTest {

    private ExtensionOpenApi extensionOpenApi;

    @BeforeEach
    void setupExtension() throws Exception {
        extensionOpenApi = new ExtensionOpenApi();

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        given(extensionLoader.getExtension(ExtensionSpider.class))
                .willReturn(mock(ExtensionSpider.class));
    }

    @Test
    void shouldImportFile() throws IOException {
        // Given
        this.nano.addHandler(new EmptyServerHandler());
        File definition = createLocalDefinition("v2/PetStore_defn.json").toFile();

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(definition, false);

        // Then
        assertThat(errors, is(empty()));
    }

    @Test
    void shouldImportMultiFileV3() throws IOException {
        // Given
        this.nano.addHandler(new EmptyServerHandler());
        File definition =
                createLocalMultiFileDefinition(
                        "v3/multi-file/", "api.yaml", "pet.api.yaml", "pet.model.yaml");

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(definition, false);

        // Then
        assertThat(errors, is(empty()));
    }

    @Test
    void shouldImportMultiFileV2() throws IOException {
        // Given
        this.nano.addHandler(new EmptyServerHandler());
        File definition =
                createLocalMultiFileDefinition("v2/multi-file/", "api.yaml", "person.yaml");

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(definition, false);

        // Then
        assertThat(errors, is(empty()));
    }

    @Test
    void shouldFailNonOpenApiURL() throws URIException {
        // Given
        this.nano.addHandler(new EmptyServerHandler());
        URI uri = new URI("http://localhost:" + this.nano.getListeningPort() + "/non-defn", false);

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(uri, null, false);

        // Then
        assertThat(errors, is(not(empty())));
    }

    @Test
    void shouldFailBadJson() {
        // Given
        File file = getResourcePath("bad-json.json").toFile();

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(file, false);

        // Then
        assertThat(errors, is(not(empty())));
    }

    @Test
    void shouldFailBadYaml() {
        // Given
        File file = getResourcePath("bad-yaml.yml").toFile();

        // When
        List<String> errors = extensionOpenApi.importOpenApiDefinition(file, false);

        // Then
        assertThat(errors, is(not(empty())));
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

    private File createLocalMultiFileDefinition(String dir, String definition, String... resources)
            throws IOException {
        Path localDefinition = createLocalDefinition(dir + definition);

        Path parentDirectory = localDefinition.getParent();
        for (String name : resources) {
            Files.write(
                    parentDirectory.resolve(name),
                    getHtml(dir + name).getBytes(StandardCharsets.UTF_8));
        }
        return localDefinition.toFile();
    }

    private static class EmptyServerHandler extends NanoServerHandler {

        EmptyServerHandler() {
            super("ServerHandler");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse("");
        }
    }
}
