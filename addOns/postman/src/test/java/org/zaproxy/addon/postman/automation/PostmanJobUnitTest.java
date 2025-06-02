/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.stringContainsInOrder;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.postman.ExtensionPostman;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class PostmanJobUnitTest extends TestUtils {

    private static MockedStatic<CommandLine> mockedCmdLine;

    private ExtensionPostman extPostman;

    @BeforeAll
    static void setUpAll() {
        mockedCmdLine = mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extPostman = mock(ExtensionPostman.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionPostman.class)).willReturn(extPostman);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        PostmanJob job = new PostmanJob();

        // Then
        assertThat(job.getType(), is(equalTo("postman")));
        assertThat(job.getName(), is(equalTo("postman")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        PostmanJob job = new PostmanJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.get("collectionFile"), is(equalTo("")));
        assertThat(params.get("collectionUrl"), is(equalTo("")));
        assertThat(params.get("variables"), is(equalTo("")));
    }

    @Test
    void shouldApplyParams() {
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        String collectionFile = "C:\\Users\\ZAPBot\\Documents\\test file.json";
        String collectionUrl = "https://example.com/test%20file.json";
        String variables = "key1=value1,key2=value2";
        String yamlStr =
                "parameters:\n"
                        + "  collectionUrl: "
                        + collectionUrl
                        + "\n"
                        + "  collectionFile: "
                        + collectionFile
                        + "\n"
                        + "  variables: "
                        + variables;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PostmanJob job = new PostmanJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getCollectionFile(), is(equalTo(collectionFile)));
        assertThat(job.getParameters().getCollectionUrl(), is(equalTo(collectionUrl)));
        assertThat(job.getParameters().getVariables(), is(equalTo(variables)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidUrl() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        String yamlStr = "parameters:\n" + "  collectionUrl: 'Invalid URL.'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PostmanJob job = new PostmanJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!postman.automation.error!")));
    }

    @Test
    void shouldFailIfInvalidFile() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationPlan plan = new AutomationPlan();
        AutomationProgress progress = plan.getProgress();
        AutomationEnvironment env = plan.getEnv();
        String yamlStr = "parameters:\n" + "  collectionFile: 'Invalid file path'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        PostmanJob job = new PostmanJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));
        job.setPlan(plan);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!postman.automation.error!")));
    }

    @Test
    void shouldCreateMinTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.registerAutomationJob(new PostmanJob());

        // When
        File f = File.createTempFile("ZAP-max-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), true);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(
                generatedTemplate,
                stringContainsInOrder(
                        "- type: postman", "collectionFile:", "collectionUrl:", "variables:"));
    }

    @Test
    void shouldCreateMaxTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        extAuto.registerAutomationJob(new PostmanJob());

        // When
        File f = File.createTempFile("ZAP-max-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), true);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(
                generatedTemplate,
                stringContainsInOrder(
                        "- type: postman", "collectionFile:", "collectionUrl:", "variables:"));
    }
}
