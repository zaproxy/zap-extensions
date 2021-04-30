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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.graphql.ExtensionGraphQl;
import org.zaproxy.addon.graphql.GraphQlParam;
import org.zaproxy.zap.utils.I18N;

class GraphQlJobUnitTest {

    private ExtensionGraphQl extGraphQl;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extGraphQl = mock(ExtensionGraphQl.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionGraphQl.class)).willReturn(extGraphQl);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
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
        GraphQlJob job = new GraphQlJob();
        String endpoint = "https://example.com/graphql/";
        String schemaFile = "C:\\Users\\ZAPBot\\Documents\\test schema.graphql";
        String schemaUrl = "https://example.com/test%20file.graphql";

        // When
        job.applyCustomParameter("endpoint", endpoint);
        job.applyCustomParameter("schemaFile", schemaFile);
        job.applyCustomParameter("schemaUrl", schemaUrl);

        // Then
        assertThat(job.getEndpoint(), is(equalTo(endpoint)));
        assertThat(job.getSchemaFile(), is(equalTo(schemaFile)));
        assertThat(job.getSchemaUrl(), is(equalTo(schemaUrl)));
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
    void shouldFailIfEmptyEndpoint() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        GraphQlJob job = new GraphQlJob();
        job.applyCustomParameter("endpoint", "");
        // The job should fail even if other parameters are specified
        job.applyCustomParameter("schemaUrl", "http://example.com/schema.graphql");
        job.applyCustomParameter("schemaFile", "/home/zap/schema.graphql");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.error.emptyendurl!")));
    }

    @Test
    void shouldFailIfInvalidEndpoint() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        GraphQlJob job = new GraphQlJob();
        job.applyCustomParameter("endpoint", "invalid url");
        job.runJob(env, null, progress);

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
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        GraphQlJob job = new GraphQlJob();
        job.applyCustomParameter("endpoint", "http://example.com/graphql");
        job.applyCustomParameter("schemaUrl", schemaUrl);
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.automation.error!")));
    }

    @Test
    void shouldFailIfInvalidSchemaFile() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        GraphQlJob job = new GraphQlJob();
        job.applyCustomParameter("endpoint", "http://example.com/graphql");
        job.applyCustomParameter("schemaFile", "Invalid file path.");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!graphql.automation.error!")));
    }
}
