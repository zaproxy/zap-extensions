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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.configuration.XMLConfiguration;
import org.mockito.ArgumentMatcher;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class AjaxSpiderJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    // Disdabled due to build issues
    private ExtensionAjax extAjax;
    private AjaxSpiderParam ajaxSpiderParam;

    // TODO Tests disabled due to build issues
    // @BeforeAll
    public static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    // @AfterAll
    public static void close() {
        mockedCmdLine.close();
    }

    // @BeforeEach
    public void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        // extAjax = mock(ExtensionAjax.class, withSettings().lenient());
        extAjax = new ExtensionAjax();
        given(extensionLoader.getExtension(ExtensionAjax.class)).willReturn(extAjax);
        ajaxSpiderParam = new AjaxSpiderParam();
        given(extAjax.getAjaxSpiderParam()).willReturn(ajaxSpiderParam);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    // @Test
    public void shouldReturnDefaultFields() {
        // Given / When
        AjaxSpiderJob job = new AjaxSpiderJob();

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getName(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));
    }

    // @Test
    public void shouldReturnCustomConfigParams() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(4)));
        assertThat(params.get("context"), is(equalTo("")));
        assertThat(params.get("url"), is(equalTo("")));
        assertThat(params.get("failIfFoundUrlsLessThan"), is(equalTo("0")));
        assertThat(params.get("warnIfFoundUrlsLessThan"), is(equalTo("0")));
    }

    // @Test
    public void shouldApplyCustomConfigParams() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "10");
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "11");
        job.applyCustomParameter("maxDuration", "12");

        // Then
        assertThat(job.getFailIfFoundUrlsLessThan(), is(equalTo(10)));
        assertThat(job.getWarnIfFoundUrlsLessThan(), is(equalTo(11)));
        assertThat(job.getMaxDuration(), is(equalTo(12)));
    }

    // @Test
    public void shouldReturnConfigParams() throws MalformedURLException {
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

    // @Test
    public void shouldRunValidJob() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setInScopeOnly(false);

        // When
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    // @Test
    public void shouldFailIfInvalidUrl() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.applyCustomParameter("url", "Not a url");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badurl!")));
    }

    // @Test
    public void shouldFailIfUnknownContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.applyCustomParameter("context", "Unknown");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
    }

    // @Test
    public void shouldUseSpecifiedContext() throws MalformedURLException, URISyntaxException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context1 = mock(Context.class);
        Context context2 = mock(Context.class);
        given(session.getNewContext("context1")).willReturn(context1);
        given(session.getNewContext("context2")).willReturn(context2);
        given(context1.isInContext(anyString())).willReturn(true);
        given(context2.isInContext(anyString())).willReturn(true);

        AjaxSpiderParam options = new AjaxSpiderParam();
        FileConfiguration tempConfig = new XMLConfiguration();
        options.load(tempConfig);

        AjaxSpiderTarget.Builder targetBuilder1 =
                AjaxSpiderTarget.newBuilder(Model.getSingleton().getSession())
                        .setContext(context1)
                        .setInScopeOnly(false)
                        .setOptions(options)
                        .setStartUri(new URI("https://www.example.com"));
        AjaxSpiderTarget target1 = targetBuilder1.build();

        AjaxSpiderTarget.Builder targetBuilder2 =
                AjaxSpiderTarget.newBuilder(Model.getSingleton().getSession())
                        .setContext(context2)
                        .setInScopeOnly(false)
                        .setOptions(options)
                        .setStartUri(new URI("https://www.example.com"));
        AjaxSpiderTarget target2 = targetBuilder2.build();

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");
        given(env.getContext("context1")).willReturn(context1);
        given(env.getContext("context2")).willReturn(context2);
        given(env.getDefaultContext()).willReturn(context1);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.applyCustomParameter("context", "context2");
        job.runJob(env, null, progress);

        // Then
        verify(extAjax, times(0))
                .startScan(any(), argThat(new TargetContextMatcher(target1)), any());
        verify(extAjax, times(1))
                .startScan(any(), argThat(new TargetContextMatcher(target2)), any());

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    private static class TargetContextMatcher implements ArgumentMatcher<AjaxSpiderTarget> {

        private AjaxSpiderTarget left;

        public TargetContextMatcher(AjaxSpiderTarget target) {
            left = target;
        }

        @Override
        public boolean matches(AjaxSpiderTarget right) {
            return (Objects.equals(left.getContext(), right.getContext()));
        }
    }

    /* TODO
    //@Test
    public void shouldUseSpecifiedUrl() throws MalformedURLException {
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        String defaultUrl = "https://www.example.com";
        String specifiedUrl = "https://www.example.com/url";

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn(defaultUrl);
        given(env.getContext(any())).willReturn(context);

        // When
        AjaxSpiderJob job = new AjaxSpiderJob();
        job.applyCustomParameter("url", specifiedUrl);
        job.runJob(env, null, progress);

        // Then
        // TODO Note that this isnt actually testing that specifiedUrl is used - couldnt get that to
        // work using aryEq or matchers :(
        verify(extAjax, times(1)).startScan(any(), any(), refEq(new Object[] {specifiedUrl}));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }
    */

    // @Test
    public void shouldExitIfSpiderTakesTooLong() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setInScopeOnly(false);

        // When
        job.applyCustomParameter("maxDuration", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    // @Test
    public void shouldWarnIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setInScopeOnly(false);

        // When
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    // @Test
    public void shouldErrorIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extAjax.isSpiderRunning()).willReturn(false);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        AjaxSpiderJob job = new AjaxSpiderJob();
        job.setInScopeOnly(false);

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extAjax));
        assertThat(job.getParamMethodName(), is("getAjaxSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
    }
}
