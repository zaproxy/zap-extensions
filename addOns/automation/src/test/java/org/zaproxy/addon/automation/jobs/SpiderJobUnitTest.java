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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import fi.iki.elonen.NanoHTTPD.Response.Status;
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
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.AutomationStatisticTest;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.SpiderJob.UrlRequester;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.extension.spider.SpiderScan;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.spider.SpiderParam;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class SpiderJobUnitTest extends TestUtils {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionSpider extSpider;
    private ExtensionLoader extensionLoader;

    private static UrlRequester urlRequester = mock(UrlRequester.class);

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
        extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extSpider = mock(ExtensionSpider.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionSpider.class)).willReturn(extSpider);

        ExtensionStats extStats = mock(ExtensionStats.class);
        given(extensionLoader.getExtension(ExtensionStats.class)).willReturn(extStats);
        Mockito.lenient().when(extStats.getInMemoryStats()).thenReturn(mock(InMemoryStats.class));

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
        assertThat(params.size(), is(equalTo(2)));
        assertThat(params.get("context"), is(equalTo("")));
        assertThat(params.get("url"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        SpiderJob job = new SpiderJob();

        // When
        job.applyCustomParameter("maxDuration", "12");

        // Then
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
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("https://www.example.com");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        // When
        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);
        job.runJob(env, progress);

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
        job.runJob(env, progress);

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
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.unknown!")));
    }

    @Test
    void shouldUseSpecifiedContext() throws MalformedURLException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context1 = mock(Context.class);
        Context context2 = mock(Context.class);
        Target target1 = new Target(context1);
        Target target2 = new Target(context2);
        ContextWrapper contextWrapper1 = new ContextWrapper(context1);
        ContextWrapper contextWrapper2 = new ContextWrapper(context2);
        contextWrapper1.addUrl("https://www.example.com");
        contextWrapper2.addUrl("https://www.example.com");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getContextWrapper("context2")).willReturn(contextWrapper2);

        // When
        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);
        job.applyCustomParameter("context", "context2");
        job.runJob(env, progress);

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
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("https://www.example.com");

        String specifiedUrl = "https://www.example.com/url";
        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        // When
        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);
        job.applyCustomParameter("url", specifiedUrl);
        job.runJob(env, progress);

        // Then
        // Note that this isnt actually testing that specifiedUrl is used - couldnt get that to
        // work using aryEq or matchers :( However later tests _do_ check the exact URLs
        verify(extSpider, times(1)).startScan(any(), any(), refEq(new Object[] {specifiedUrl}));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldExitIfSpiderTakesTooLong() throws MalformedURLException {
        // Given
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("https://www.example.com");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(false);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);

        // When
        job.applyCustomParameter("maxDuration", "1");
        job.runJob(env, progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldTestAddedUrlsStatistic() {
        // Given
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("https://www.example.com");
        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(extSpider.getScan(1)).willReturn(spiderScan);
        AutomationProgress progress = new AutomationProgress();
        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);

        // When
        job.addTest(
                new AutomationStatisticTest(
                        "automation.spider.urls.added", null, ">", 1, "error", job.getType()));
        job.logTestsToProgress(progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.tests.stats.fail!"));
    }

    @Test
    void shouldRequestContextUrl() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        startServer();
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("http://localhost:" + nano.getListeningPort() + "/top");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        SpiderJob job = new SpiderJob();

        TestServerHandler testHandler = new TestServerHandler("/");

        nano.addHandler(testHandler);

        // When
        job.runJob(env, progress);

        stopServer();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(testHandler.wasCalled(), is(equalTo(true)));
    }

    @Test
    void shouldRequestContextUrls() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        startServer();
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("http://localhost:" + nano.getListeningPort() + "/1");
        contextWrapper.addUrl("http://localhost:" + nano.getListeningPort() + "/2");
        contextWrapper.addUrl("http://localhost:" + nano.getListeningPort() + "/3");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        SpiderJob job = new SpiderJob();

        TestServerHandler testHandler1 = new TestServerHandler("/1");
        TestServerHandler testHandler2 = new TestServerHandler("/2");
        TestServerHandler testHandler3 = new TestServerHandler("/3");

        nano.addHandler(testHandler1);
        nano.addHandler(testHandler2);
        nano.addHandler(testHandler3);

        // When
        job.runJob(env, progress);

        stopServer();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(testHandler1.wasCalled(), is(equalTo(true)));
        assertThat(testHandler2.wasCalled(), is(equalTo(true)));
        assertThat(testHandler3.wasCalled(), is(equalTo(true)));
    }

    @Test
    void shouldFailIfInvalidHost() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("http://null.example.com/");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        SpiderJob job = new SpiderJob();

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!automation.error.spider.url.badhost!")));
    }

    @Test
    void shouldFailIfForbiddenResponse() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        startServer();
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        contextWrapper.addUrl("http://localhost:" + nano.getListeningPort() + "/top");

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        SpiderJob job = new SpiderJob();

        TestServerHandler testHandler = new TestServerHandler("/", Response.Status.FORBIDDEN);

        nano.addHandler(testHandler);

        // When
        job.runJob(env, progress);

        stopServer();

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(testHandler.wasCalled(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.spider.url.notok!")));
    }

    private static class TestServerHandler extends NanoServerHandler {

        private boolean called = false;
        private Status status = Response.Status.OK;

        public TestServerHandler(String name) {
            super(name);
        }

        public TestServerHandler(String name, Status status) {
            super(name);
            this.status = status;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            called = true;
            return newFixedLengthResponse(status, NanoHTTPD.MIME_HTML, "<html></html>");
        }

        public boolean wasCalled() {
            return called;
        }
    }
}
