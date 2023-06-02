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
package org.zaproxy.zap.extension.spiderAjax.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.quality.Strictness;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.extension.spiderAjax.SpiderThread;
import org.zaproxy.zap.extension.spiderAjax.internal.ContextDataManager;
import org.zaproxy.zap.extension.spiderAjax.internal.ExcludedElement;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class AjaxSpiderJobUnitTest {

    private ExtensionLoader extensionLoader;
    private ContextDataManager contextDataManager;
    private ExtensionAjax extAjax;
    private AjaxSpiderParam ajaxSpiderParam;

    @AfterAll
    static void afterAll() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extAjax = mock(ExtensionAjax.class);
        given(extensionLoader.getExtension(ExtensionAjax.class)).willReturn(extAjax);
        ajaxSpiderParam = mock(AjaxSpiderParam.class);
        given(extAjax.getAjaxSpiderParam()).willReturn(ajaxSpiderParam);
        contextDataManager = mock(ContextDataManager.class);
        given(extAjax.getContextDataManager()).willReturn(contextDataManager);
        Model model = mock(Model.class);
        given(model.getSession()).willReturn(mock(Session.class));
        given(extAjax.getModel()).willReturn(model);

        ExtensionStats extStats = mock(ExtensionStats.class);
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);
        Mockito.lenient().when(extStats.getInMemoryStats()).thenReturn(mock(InMemoryStats.class));

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        AjaxSpiderJob job = new AjaxSpiderJob();

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getName(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(4)));
        assertThat(params.get("context"), is(equalTo("")));
        assertThat(params.get("url"), is(equalTo("")));
        assertThat(params.get("user"), is(equalTo("")));
        assertThat(params.get("runOnlyIfModern"), is(equalTo("false")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                "parameters:\n"
                        + "  context: context\n  url: url\n  user: user\n  runOnlyIfModern: true";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getContext(), is(equalTo("context")));
        assertThat(job.getParameters().getUrl(), is(equalTo("url")));
        assertThat(job.getParameters().getUser(), is(equalTo("user")));
        assertThat(job.getParameters().getRunOnlyIfModern(), is(equalTo(Boolean.TRUE)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnConfigParams() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();

        // When
        Map<String, String> params =
                job.getConfigParameters(new AjaxSpiderParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(params.size(), is(equalTo(10)));
        assertThat(params.containsKey("maxDuration"), is(equalTo(true)));
        assertThat(params.containsKey("browserId"), is(equalTo(true)));
        assertThat(params.containsKey("clickDefaultElems"), is(equalTo(true)));
        assertThat(params.containsKey("clickElemsOnce"), is(equalTo(true)));
        assertThat(params.containsKey("eventWait"), is(equalTo(true)));
        assertThat(params.containsKey("maxCrawlDepth"), is(equalTo(true)));
        assertThat(params.containsKey("maxCrawlStates"), is(equalTo(true)));
        assertThat(params.containsKey("maxDuration"), is(equalTo(true)));
        assertThat(params.containsKey("numberOfBrowsers"), is(equalTo(true)));
        assertThat(params.containsKey("randomInputs"), is(equalTo(true)));
        assertThat(params.containsKey("reloadWait"), is(equalTo(true)));
    }

    private static class AjaxSpiderParamWrapper {
        @SuppressWarnings("unused")
        public AjaxSpiderParam getAjaxSpiderParam() {
            return new AjaxSpiderParam();
        }
    }

    @Test
    void shouldVerifyWithoutParameters() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setJobData(null);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors(), is(empty()));
    }

    @Test
    void shouldRunValidJob() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getContext()).willReturn(context);
        String url = "http://example.com";
        given(contextWrapper.getUrls()).willReturn(List.of(url));
        given(context.isInContext(url)).willReturn(true);
        given(extAjax.isSpiderRunning()).willReturn(false);

        given(extAjax.createSpiderThread(anyString(), any(), any()))
                .willReturn(mock(SpiderThread.class));

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(url)).willReturn(url);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setInScopeOnly(false);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidUrl() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setUrl("Not a url");
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badurl!")));
    }

    @Test
    void shouldFailIfUnknownContext() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setContext("Unknown");
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
    }

    @Test
    void shouldUseSpecifiedContext() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context1 = mock(Context.class);
        Context context2 = mock(Context.class);
        given(context2.isInContext(anyString())).willReturn(true);
        ContextWrapper contextWrapper1 = new ContextWrapper(context1);
        ContextWrapper contextWrapper2 = new ContextWrapper(context2);

        AjaxSpiderParam options = new AjaxSpiderParam();
        FileConfiguration tempConfig = new XMLConfiguration();
        options.load(tempConfig);

        given(extAjax.createSpiderThread(anyString(), any(), any()))
                .willReturn(mock(SpiderThread.class));

        AutomationProgress progress = new AutomationProgress();

        String url = "https://www.example.com";
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(url)).willReturn(url);
        given(env.getContextWrapper("context1")).willReturn(contextWrapper1);
        given(env.getContextWrapper("context2")).willReturn(contextWrapper2);
        given(env.getDefaultContext()).willReturn(context1);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setUrl(url);
        job.getParameters().setContext("context2");
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<AjaxSpiderTarget> targetCaptor =
                ArgumentCaptor.forClass(AjaxSpiderTarget.class);
        verify(extAjax).createSpiderThread(any(), targetCaptor.capture(), any());
        assertThat(targetCaptor.getValue().getContext(), is(equalTo(context2)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldUseSpecifiedUrl() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        given(context.isInContext(anyString())).willReturn(true);
        String defaultUrl = "https://www.example.com";
        String specifiedUrl = "https://www.example.com/url";

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(specifiedUrl)).willReturn(specifiedUrl);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getContext()).willReturn(context);
        given(contextWrapper.getUrls()).willReturn(List.of(defaultUrl));
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        given(extAjax.createSpiderThread(anyString(), any(), any()))
                .willReturn(mock(SpiderThread.class));

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setUrl(specifiedUrl);
        job.runJob(env, progress);

        // Then
        ArgumentCaptor<AjaxSpiderTarget> targetCaptor =
                ArgumentCaptor.forClass(AjaxSpiderTarget.class);
        verify(extAjax).createSpiderThread(any(), targetCaptor.capture(), any());
        assertThat(targetCaptor.getValue().getStartUri().toString(), is(equalTo(specifiedUrl)));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldExitIfSpiderTakesTooLong() {
        // Given
        Context context = mock(Context.class);
        given(context.isInContext(anyString())).willReturn(true);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getContext()).willReturn(context);
        String url = "https://example.com";
        given(contextWrapper.getUrls()).willReturn(List.of(url));

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(url)).willReturn(url);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setInScopeOnly(false);

        SpiderThread spiderThread = mock(SpiderThread.class);
        given(spiderThread.isRunning()).willReturn(true);
        given(extAjax.createSpiderThread(anyString(), any(), any())).willReturn(spiderThread);

        // When
        job.getParameters().setMaxDuration(1);
        job.runJob(env, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldTestAddedUrlsStatistic() {
        // Given

        AutomationProgress progress = new AutomationProgress();

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.getParameters().setInScopeOnly(false);

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any()))
                .willAnswer(
                        new Answer<>() {
                            @Override
                            public String answer(InvocationOnMock invocation) throws Throwable {
                                return invocation.getArgument(0);
                            }
                        });
        job.setEnv(env);

        // When
        job.addTest(
                new AutomationStatisticTest(
                        "spiderAjax.urls.added", null, ">", 1, "warn", job, progress));
        job.logTestsToProgress(progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "''", "\n  - A"})
    void shouldHandleInvalidExcludedElementsFormat(String dataExcludedElements) {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String yamlStr = "parameters:\n" + "  excludedElements: " + dataExcludedElements + "\n";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getExcludedElements(), hasSize(0));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains("!spiderajax.automation.error.excludedelements.format!"));
    }

    @Test
    void shouldVerifyExcludedElements() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                "parameters:\n"
                        + "  excludedElements:\n"
                        + "  - element: \"a\"\n"
                        + "    xpath: \"//a[@id='logout' and @class='logout']\"\n"
                        + "  - description: \"E2\"\n"
                        + "    text: \"Click Y\"\n"
                        + "  - description: \"E2a\"\n"
                        + "    element: \"a\"\n"
                        + "  - description: \"X0\"\n"
                        + "    element: \"X0\"\n"
                        + "    attributeValue: \"B\"\n"
                        + "  - description: \"X1\"\n"
                        + "    element: \"X1\"\n"
                        + "    attributeName: \"B\"\n"
                        + "  - description: \"X2\"\n"
                        + "    element: \"X\"\n"
                        + "    text: \"B\"\n"
                        + "  - description: \"X2\"\n"
                        + "    element: \"X\"\n"
                        + "    text: \"B\"";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getExcludedElements(), hasSize(1));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!spiderajax.automation.error.excludedelements.description!",
                        "!spiderajax.automation.error.excludedelements.element!",
                        "!spiderajax.automation.error.excludedelements.data!",
                        "!spiderajax.automation.error.excludedelements.attribute!",
                        "!spiderajax.automation.error.excludedelements.attribute!",
                        "!spiderajax.automation.error.excludedelements.duplicated!"));
    }

    @Test
    void shouldApplyExcludedElements() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AjaxSpiderJob job = new AjaxSpiderJob();
        ExcludedElementAuto excludedElement = new ExcludedElementAuto();
        excludedElement.setDescription("Description");
        excludedElement.setElement("Element");
        excludedElement.setText("Text");
        job.getParameters().setExcludedElements(List.of(excludedElement));

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        AutomationPlan plan = mock(AutomationPlan.class);
        given(plan.getEnv()).willReturn(env);
        job.setPlan(plan);

        Context context = mock(Context.class);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(contextWrapper.getContext()).willReturn(context);

        // When
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getExcludedElements(), hasSize(1));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<ExcludedElement>> captorExcludedElements =
                ArgumentCaptor.forClass(List.class);
        verify(contextDataManager)
                .setExcludedElements(eq(context), captorExcludedElements.capture());
        ExcludedElement excludedElementApplied = captorExcludedElements.getValue().get(0);
        assertThat(excludedElementApplied.getDescription(), is(equalTo("Description")));
        assertThat(excludedElementApplied.getElement(), is(equalTo("Element")));
        assertThat(excludedElementApplied.getText(), is(equalTo("Text")));
    }

    @Test
    void shouldSavePlanWithExcludedElements(@TempDir Path tempDir) throws Exception {
        // Given
        Path planFile = tempDir.resolve("plan.yaml");
        AutomationPlan plan = new AutomationPlan();
        plan.setFile(planFile.toFile());
        AjaxSpiderJob job = new AjaxSpiderJob();
        plan.addJob(job);
        ExcludedElementAuto excludedElement = new ExcludedElementAuto();
        excludedElement.setDescription("Description");
        excludedElement.setElement("Element");
        excludedElement.setXpath("XPath");
        excludedElement.setText("Text");
        excludedElement.setAttributeName("Attribute Name");
        excludedElement.setAttributeValue("Attribute Value");
        job.getParameters().setExcludedElements(List.of(excludedElement));

        // When
        plan.save();

        // Then
        assertThat(
                Files.readString(planFile),
                containsString(
                        "    excludedElements:\n"
                                + "    - description: \"Description\"\n"
                                + "      element: \"Element\"\n"
                                + "      xpath: \"XPath\"\n"
                                + "      text: \"Text\"\n"
                                + "      attributeName: \"Attribute Name\"\n"
                                + "      attributeValue: \"Attribute Value\""));
    }
}
