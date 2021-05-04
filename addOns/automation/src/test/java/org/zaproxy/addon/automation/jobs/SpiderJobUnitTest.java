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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.refEq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.net.MalformedURLException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.spider.SpiderParam;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class SpiderJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionSpider extSpider;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extSpider = mock(ExtensionSpider.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionSpider.class)).willReturn(extSpider);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given

        // When
        SpiderJob job = new SpiderJob();

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getName(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(4)));
        assertThat(params.get("context"), is(equalTo("")));
        assertThat(params.get("url"), is(equalTo("")));
        assertThat(params.get("failIfFoundUrlsLessThan"), is(equalTo("0")));
        assertThat(params.get("warnIfFoundUrlsLessThan"), is(equalTo("0")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "10");
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "11");
        job.applyCustomParameter("maxDuration", "12");

        // Then
        assertThat(job.getFailIfFoundUrlsLessThan(), is(equalTo(10)));
        assertThat(job.getWarnIfFoundUrlsLessThan(), is(equalTo(11)));
        assertThat(job.getMaxDuration(), is(equalTo(12)));
    }

    @Test
    void shouldReturnConfigParams() throws MalformedURLException {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        Map<String, String> params =
                job.getConfigParameters(new SpiderParamWrapper(), job.getParamMethodName());

        // Then
        assertThat(params.size(), is(equalTo(18)));
        assertThat(params.containsKey("maxDuration"), is(equalTo(true)));
        assertThat(params.containsKey("maxDepth"), is(equalTo(true)));
        assertThat(params.containsKey("maxChildren"), is(equalTo(true)));
        assertThat(params.containsKey("acceptCookies"), is(equalTo(true)));
        assertThat(params.containsKey("handleODataParametersVisited"), is(equalTo(true)));
        assertThat(params.containsKey("handleParameters"), is(equalTo(true)));
        assertThat(params.containsKey("maxParseSizeBytes"), is(equalTo(true)));
        assertThat(params.containsKey("parseComments"), is(equalTo(true)));
        assertThat(params.containsKey("parseGit"), is(equalTo(true)));
        assertThat(params.containsKey("parseRobotsTxt"), is(equalTo(true)));
        assertThat(params.containsKey("parseSitemapXml"), is(equalTo(true)));
        assertThat(params.containsKey("parseSVNEntries"), is(equalTo(true)));
        assertThat(params.containsKey("postForm"), is(equalTo(true)));
        assertThat(params.containsKey("processForm"), is(equalTo(true)));
        assertThat(params.containsKey("requestWaitTime"), is(equalTo(true)));
        assertThat(params.containsKey("sendRefererHeader"), is(equalTo(true)));
        assertThat(params.containsKey("threadCount"), is(equalTo(true)));
        assertThat(params.containsKey("userAgent"), is(equalTo(true)));
    }

    private static class SpiderParamWrapper {
        @SuppressWarnings("unused")
        public SpiderParam getSpiderParam() {
            return new SpiderParam();
        }
    }

    @Test
    void shouldRunValidJob() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        // When
        SpiderJob job = new SpiderJob();
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidUrl() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        SpiderJob job = new SpiderJob();
        job.applyCustomParameter("url", "Not a url");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badurl!")));
    }

    @Test
    void shouldFailIfUnknownContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        // When
        SpiderJob job = new SpiderJob();
        job.applyCustomParameter("context", "Unknown");
        job.runJob(env, null, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
    }

    @Test
    void shouldUseSpecifiedContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context1 = mock(Context.class);
        Context context2 = mock(Context.class);
        given(session.getNewContext("context1")).willReturn(context1);
        given(session.getNewContext("context2")).willReturn(context2);
        Target target1 = new Target(context1);
        Target target2 = new Target(context2);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");
        given(env.getContext("context1")).willReturn(context1);
        given(env.getContext("context2")).willReturn(context2);
        given(env.getDefaultContext()).willReturn(context1);

        // When
        SpiderJob job = new SpiderJob();
        job.applyCustomParameter("context", "context2");
        job.runJob(env, null, progress);

        // Then
        verify(extSpider, times(0))
                .startScan(argThat(new TargetContextMatcher(target1)), any(), any());
        verify(extSpider, times(1))
                .startScan(argThat(new TargetContextMatcher(target2)), any(), any());

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    private static class TargetContextMatcher implements ArgumentMatcher<Target> {

        private Target left;

        public TargetContextMatcher(Target target) {
            left = target;
        }

        @Override
        public boolean matches(Target right) {
            return (Objects.equals(left.getContext(), right.getContext()));
        }
    }

    @Test
    void shouldUseSpecifiedUrl() throws MalformedURLException {
        Constant.messages = new I18N(Locale.ENGLISH);
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        String defaultUrl = "https://www.example.com";
        String specifiedUrl = "https://www.example.com/url";
        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn(defaultUrl);
        given(env.getContext(any())).willReturn(context);

        // When
        SpiderJob job = new SpiderJob();
        job.applyCustomParameter("url", specifiedUrl);
        job.runJob(env, null, progress);

        // Then
        // TODO Note that this isnt actually testing that specifiedUrl is used - couldnt get that to
        // work using aryEq or matchers :(
        verify(extSpider, times(1)).startScan(any(), any(), refEq(new Object[] {specifiedUrl}));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldExitIfSpiderTakesTooLong() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(false);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("maxDuration", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldWarnIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("warnIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldErrorIfLessUrlsFoundThanExpected() throws MalformedURLException {
        // Given
        Session session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getUrlStringForContext(any())).willReturn("https://www.example.com");

        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("failIfFoundUrlsLessThan", "1");
        job.runJob(env, null, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
    }
}
