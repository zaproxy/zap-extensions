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
package org.zaproxy.zap.extension.openapi.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class OpenApiJobUnitTest extends TestUtils {

    private ExtensionOpenApi extOpenApi;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extOpenApi = mock(ExtensionOpenApi.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionOpenApi.class)).willReturn(extOpenApi);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        OpenApiJob job = new OpenApiJob();

        // Then
        assertThat(job.getType(), is(equalTo("openapi")));
        assertThat(job.getName(), is(equalTo("openapi")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        OpenApiJob job = new OpenApiJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.get("apiFile"), is(equalTo("")));
        assertThat(params.get("apiUrl"), is(equalTo("")));
        assertThat(params.get("targetUrl"), is(equalTo("")));
    }

    @Test
    void shouldApplyParams() {
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        String apiFile = "C:\\Users\\ZAPBot\\Documents\\test file.json";
        String apiUrl = "https://example.com/test%20file.json";
        String targetUrl = "https://example.com/endpoint/";
        String yamlStr =
                "parameters:\n"
                        + "  apiUrl: "
                        + apiUrl
                        + "\n"
                        + "  apiFile: "
                        + apiFile
                        + "\n"
                        + "  targetUrl: "
                        + targetUrl;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        OpenApiJob job = new OpenApiJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getApiFile(), is(equalTo(apiFile)));
        assertThat(job.getParameters().getApiUrl(), is(equalTo(apiUrl)));
        assertThat(job.getParameters().getTargetUrl(), is(equalTo(targetUrl)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidUrl() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        String yamlStr = "parameters:\n" + "  apiUrl: 'Invalid URL.'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        OpenApiJob job = new OpenApiJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!openapi.automation.error.url!")));
    }

    @Test
    void shouldFailIfInvalidFile() {
        // Given
        mockMessages(new ExtensionOpenApi());
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        String yamlStr = "parameters:\n" + "  apiFile: 'Invalid file path'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        OpenApiJob job = new OpenApiJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("Job openapi cannot read file: Invalid file path")));
    }
}
