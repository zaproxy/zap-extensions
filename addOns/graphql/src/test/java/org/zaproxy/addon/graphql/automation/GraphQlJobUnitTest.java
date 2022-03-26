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
package org.zaproxy.addon.graphql.automation;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.graphql.ExtensionGraphQl;
import org.zaproxy.addon.graphql.GraphQlParam;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class GraphQlJobUnitTest extends TestUtils {

    private ExtensionGraphQl extGraphQl;
    private GraphQlServer graphQlServer;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extGraphQl = mock(ExtensionGraphQl.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionGraphQl.class)).willReturn(extGraphQl);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        graphQlServer = new GraphQlServer();
    }

    @AfterEach
    void cleanUp() {
        stopServer();
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        GraphQlJob job = new GraphQlJob();

        // Then
        assertThat(job.getType(), is(equalTo("graphql")));
        assertThat(job.getName(), is(equalTo("graphql")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extGraphQl));
        assertThat(job.getParamMethodName(), is("getParam"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        GraphQlJob job = new GraphQlJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.get("endpoint"), is(equalTo("")));
        assertThat(params.get("schemaUrl"), is(equalTo("")));
        assertThat(params.get("schemaFile"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        String endpoint = "https://example.com/graphql/";
        String schemaFile = "C:\\Users\\ZAPBot\\Documents\\test schema.graphql";
        String schemaUrl = "https://example.com/test%20file.graphql";
        String yamlStr =
                "parameters:\n"
                        + "  endpoint: "
                        + endpoint
                        + "\n"
                        + "  schemaFile: "
                        + schemaFile
                        + "\n"
                        + "  schemaUrl: "
                        + schemaUrl;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        GraphQlJob job = new GraphQlJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getEndpoint(), is(equalTo(endpoint)));
        assertThat(job.getParameters().getSchemaFile(), is(equalTo(schemaFile)));
        assertThat(job.getParameters().getSchemaUrl(), is(equalTo(schemaUrl)));
    }

    @Test
    void shouldReplaceVarInEndpointWhenRunning() throws IOException {
        // Given
        String server = serverWithGraphQl();
        String endpoint = "${server}endpoint";
        String schemaUrl = server + "schemaUrl";
        GraphQlJob job =
                createGraphQlJob(
                        "parameters:\n"
                                + "  endpoint: "
                                + endpoint
                                + "\n"
                                + "  schemaUrl: "
                                + schemaUrl);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        env.getData().getVars().put("server", server);
        job.verifyParameters(progress);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(graphQlServer.getAccessedUrls(), contains("/schemaUrl", "/endpoint"));
    }

    @Test
    void shouldReplaceVarInSchemaFileWhenRunning(@TempDir Path dir) throws IOException {
        // Given
        String server = serverWithGraphQl();
        String endpoint = server + "endpoint";
        String schemaFile = "${schemaFile}";
        GraphQlJob job =
                createGraphQlJob(
                        "parameters:\n"
                                + "  endpoint: "
                                + endpoint
                                + "\n"
                                + "  schemaFile: "
                                + schemaFile);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        Path file = dir.resolve("schema");
        Files.write(file, "type Query { name: String }".getBytes(StandardCharsets.UTF_8));
        env.getData().getVars().put("schemaFile", file.toString());
        job.verifyParameters(progress);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(graphQlServer.getAccessedUrls(), contains("/endpoint"));
    }

    @Test
    void shouldReplaceVarInSchemaUrlWhenRunning() throws IOException {
        // Given
        String server = serverWithGraphQl();
        String endpoint = server + "endpoint";
        String schemaUrl = "${server}schemaUrl";
        GraphQlJob job =
                createGraphQlJob(
                        "parameters:\n"
                                + "  endpoint: "
                                + endpoint
                                + "\n"
                                + "  schemaUrl: "
                                + schemaUrl);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        env.getData().getVars().put("server", server);
        job.verifyParameters(progress);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(graphQlServer.getAccessedUrls(), contains("/schemaUrl", "/endpoint"));
    }

    @Test
    void shouldReturnConfigParams() {
        // Given
        GraphQlJob job = new GraphQlJob();

        // When
        Map<String, String> params =
                job.getConfigParameters(new GraphQlParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(params.size(), is(equalTo(8)));
        assertThat(params.containsKey("argsType"), is(equalTo(true)));
        assertThat(params.containsKey("lenientMaxQueryDepthEnabled"), is(equalTo(true)));
        assertThat(params.containsKey("maxAdditionalQueryDepth"), is(equalTo(true)));
        assertThat(params.containsKey("maxArgsDepth"), is(equalTo(true)));
        assertThat(params.containsKey("maxQueryDepth"), is(equalTo(true)));
        assertThat(params.containsKey("optionalArgsEnabled"), is(equalTo(true)));
        assertThat(params.containsKey("querySplitType"), is(equalTo(true)));
        assertThat(params.containsKey("requestMethod"), is(equalTo(true)));
    }

    private static class GraphQlParamWrapper {
        @SuppressWarnings("unused")
        public GraphQlParam getParam() {
            return new GraphQlParam();
        }
    }

    @Test
    void shouldInfoIfEmptyEndpoint() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        GraphQlJob job = new GraphQlJob();
        job.applyCustomParameter("endpoint", "");
        // The job should info even if other parameters are specified
        job.applyCustomParameter("schemaUrl", "http://example.com/schema.graphql");
        job.applyCustomParameter("schemaFile", "/home/zap/schema.graphql");
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getInfos().size(), is(equalTo(1)));
        assertThat(progress.getInfos().get(0), is(equalTo("!graphql.info.emptyendurl!")));
    }

    @Test
    void shouldFailIfInvalidEndpoint() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        String yamlStr = "parameters:\n" + "  endpoint: 'invalid url'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        GraphQlJob job = new GraphQlJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.automation.error!")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "https://example.com/test file.graphql"})
    void shouldFailIfInvalidSchemaUrl(String schemaUrl) {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        String yamlStr =
                "parameters:\n"
                        + "  endpoint: 'http://example.com/graphql'\n"
                        + "  schemaUrl: "
                        + schemaUrl;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        GraphQlJob job = new GraphQlJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.automation.error!")));
    }

    @Test
    void shouldFailIfInvalidSchemaFile() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        String yamlStr =
                "parameters:\n"
                        + "  endpoint: 'http://example.com/graphql'\n"
                        + "  schemaFile: 'Invalid file path.'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        GraphQlJob job = new GraphQlJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.automation.error!")));
    }

    private String serverWithGraphQl() throws IOException {
        startServer();
        nano.addHandler(graphQlServer);
        return "http://localhost:" + nano.getListeningPort() + "/";
    }

    private static GraphQlJob createGraphQlJob(String data) {
        GraphQlJob job = new GraphQlJob();
        job.setJobData(new Yaml().load(data));
        return job;
    }

    private static class GraphQlServer extends NanoServerHandler {

        private Set<String> accessedUrls;

        GraphQlServer() {
            super("");
            accessedUrls = new HashSet<>();
        }

        Set<String> getAccessedUrls() {
            return accessedUrls;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            accessedUrls.add(session.getUri());
            return newFixedLengthResponse(
                    Status.OK, "application/graphql", "type Query { name: String }");
        }
    }
}
