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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.BDDMockito.any;
import static org.mockito.BDDMockito.anyInt;
import static org.mockito.BDDMockito.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ascan.VariantFactory;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralNodeModifier;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtensionOpenApiTest extends AbstractServerTest {

    private Model model;
    private ExtensionOpenApi extensionOpenApi;
    private TableHistory tableHistory;

    @BeforeEach
    void setupExtension() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);

        extensionOpenApi = new ExtensionOpenApi();

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        given(extensionLoader.getExtension(ExtensionSpider.class))
                .willReturn(mock(ExtensionSpider.class));

        tableHistory = mock(TableHistory.class);
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(mock(TableAlert.class));
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

    @Test
    void shouldImportFileDefinitionWithIssues() throws Exception {
        // Given
        this.nano.addHandler(new EmptyServerHandler());
        File file = createLocalDefinition("defn-with-warns.yml").toFile();
        RecordHistory recordHistory = mock(RecordHistory.class);
        given(tableHistory.write(anyLong(), anyInt(), any()))
                .willReturn(recordHistory, recordHistory);
        given(model.getVariantFactory()).willReturn(new VariantFactory());
        // When
        OpenApiResults results = extensionOpenApi.importOpenApiDefinitionV2(file, null, false);
        // Then
        assertThat(results.getErrors(), is(not(empty())));
        assertThat(results.getHistoryReferences(), hasSize(1));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldGenerateDataDrivenNodesOnContext(String target) throws IOException {
        // Given
        File file = createLocalDefinition("v3/PetStore_defn.json").toFile();
        Context ctx = createContext();
        String serverUrl = "http://localhost:" + nano.getListeningPort();
        String targetUrl = target != null ? serverUrl + "/v1" : null;
        String expectedUrl = target != null ? targetUrl : serverUrl + "/PetStore";

        // When
        extensionOpenApi.importOpenApiDefinition(file, targetUrl, false, ctx.getId());

        // Then
        assertThat(
                ctx.getDataDrivenNodes(),
                contains(
                        expectedUrl + "(/pet/)(.+?)(/.*)",
                        expectedUrl + "(/store/order/)(.+?)(/.*)",
                        expectedUrl + "(/user/)(.+?)(/.*)"));
    }

    @Test
    void shouldGenerateDataDrivenNodesOnContextForMultiVarPath() throws IOException {
        // Given
        File file = createLocalDefinition("v3/MultiVarPath_defn.yaml").toFile();
        Context ctx = createContext();
        String serverUrl = "http://localhost:" + nano.getListeningPort();

        // When
        extensionOpenApi.importOpenApiDefinition(file, null, false, ctx.getId());

        // Then
        assertThat(
                ctx.getDataDrivenNodes(),
                contains(
                        serverUrl + "(/api/stuff/.+?/subthing/)(.+?)(/.*)",
                        serverUrl + "(/api/stuff/)(.+?)(/.*)"));
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

    private static Context createContext() {
        return Model.getSingleton().getSession().getNewContext("Test Context");
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

    private static Matcher<List<StructuralNodeModifier>> contains(String... regexes) {
        List<String> expectedValues = new ArrayList<>();
        expectedValues.addAll(Arrays.asList(regexes));
        Collections.sort(expectedValues);

        return new BaseMatcher<List<StructuralNodeModifier>>() {

            @Override
            public boolean matches(Object actualValue) {
                @SuppressWarnings("unchecked")
                List<StructuralNodeModifier> values = (List<StructuralNodeModifier>) actualValue;
                if (values.isEmpty()) {
                    return false;
                }

                List<String> matched = new ArrayList<>(expectedValues);
                for (StructuralNodeModifier value : values) {
                    if (!matched.remove(value.getPattern().pattern())) {
                        return false;
                    }
                }
                return matched.isEmpty();
            }

            @Override
            public void describeTo(Description description) {
                description
                        .appendText("the DDN regular expressions to be ")
                        .appendValue(expectedValues);
            }

            @Override
            public void describeMismatch(Object item, Description description) {
                @SuppressWarnings("unchecked")
                List<StructuralNodeModifier> values = (List<StructuralNodeModifier>) item;
                if (values.isEmpty()) {
                    description.appendText("had no DDNs");
                } else {
                    description
                            .appendText("were ")
                            .appendValue(
                                    values.stream()
                                            .map(StructuralNodeModifier::getPattern)
                                            .map(Pattern::pattern)
                                            .sorted()
                                            .collect(Collectors.toList()));
                }
            }
        };
    }
}
