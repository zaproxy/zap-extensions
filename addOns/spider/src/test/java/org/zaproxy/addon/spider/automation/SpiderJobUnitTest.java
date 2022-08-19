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
package org.zaproxy.addon.spider.automation;

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
import java.util.LinkedHashMap;
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
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.spider.ExtensionSpider2;
import org.zaproxy.addon.spider.SpiderParam;
import org.zaproxy.addon.spider.SpiderScan;
import org.zaproxy.addon.spider.automation.SpiderJob.UrlRequester;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class SpiderJobUnitTest extends TestUtils {

    private static MockedStatic<CommandLine> mockedCmdLine;
    private ExtensionSpider2 extSpider;
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
        extSpider = mock(ExtensionSpider2.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionSpider2.class)).willReturn(extSpider);

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

        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        SpiderJob job = new SpiderJob();
        job.getParameters().setUrl("Not a url");
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

        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        SpiderJob job = new SpiderJob();
        job.getParameters().setContext("Unknown");
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
        job.getParameters().setContext("context2");
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
        String url = "https://www.example.com";
        contextWrapper.addUrl(url);

        String specifiedUrl = "https://www.example.com/url";
        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(env.replaceVars(url)).willReturn(url);
        given(env.replaceVars(specifiedUrl)).willReturn(specifiedUrl);

        // When
        SpiderJob job = new SpiderJob();
        job.setUrlRequester(urlRequester);
        job.getParameters().setUrl(specifiedUrl);
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
        job.getParameters().setMaxDuration(1);
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
        job.setEnv(new AutomationEnvironment(progress));
        job.setUrlRequester(urlRequester);

        // When
        job.addTest(
                new AutomationStatisticTest(
                        "automation.spider.urls.added", null, ">", 1, "error", job, progress));
        job.logTestsToProgress(progress);

        // Then
        assertThat(job.getType(), is(equalTo("spider")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(extSpider));
        assertThat(job.getParamMethodName(), is("getSpiderParam"));

        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.tests.fail!"));
    }

    @Test
    void shouldRequestContextUrl() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        startServer();
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        String url = "http://localhost:" + nano.getListeningPort() + "/top";
        contextWrapper.addUrl(url);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(env.replaceVars(url)).willReturn(url);

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
        String url1 = "http://localhost:" + nano.getListeningPort() + "/1";
        String url2 = "http://localhost:" + nano.getListeningPort() + "/2";
        String url3 = "http://localhost:" + nano.getListeningPort() + "/3";
        contextWrapper.addUrl(url1);
        contextWrapper.addUrl(url2);
        contextWrapper.addUrl(url3);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(env.replaceVars(url1)).willReturn(url1);
        given(env.replaceVars(url2)).willReturn(url2);
        given(env.replaceVars(url3)).willReturn(url3);

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
        String url = "http://null.example.com/";
        contextWrapper.addUrl(url);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(env.replaceVars(url)).willReturn(url);

        SpiderJob job = new SpiderJob();

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!spider.automation.error.url.badhost!")));
    }

    @Test
    void shouldFailIfForbiddenResponse() throws Exception {
        ExtensionHistory extHistory = mock(ExtensionHistory.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);

        startServer();
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = new ContextWrapper(context);
        String url = "http://localhost:" + nano.getListeningPort() + "/top";
        contextWrapper.addUrl(url);

        given(extSpider.startScan(any(), any(), any())).willReturn(1);

        SpiderScan spiderScan = mock(SpiderScan.class);
        given(spiderScan.isStopped()).willReturn(true);
        given(extSpider.getScan(1)).willReturn(spiderScan);

        AutomationProgress progress = new AutomationProgress();

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);
        given(env.replaceVars(url)).willReturn(url);

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
        assertThat(progress.getErrors().get(0), is(equalTo("!spider.automation.error.url.notok!")));
    }

    @Test
    void shouldVerifyAllOfTheParameters() {
        String yamlStr =
                "parameters:\n"
                        + "  context: context1\n"
                        + "  url: url1\n"
                        + "  maxDuration: 2\n"
                        + "  maxDepth: 2\n"
                        + "  maxChildren: 2\n"
                        + "  acceptCookies: true\n"
                        + "  handleODataParametersVisited: true\n"
                        + "  handleParameters: ignore_completely\n"
                        + "  maxParseSizeBytes: 2\n"
                        + "  parseComments: true\n"
                        + "  parseGit: true\n"
                        + "  parseRobotsTxt: true\n"
                        + "  parseSitemapXml: true\n"
                        + "  parseSVNEntries: true\n"
                        + "  postForm: true\n"
                        + "  processForm: true\n"
                        + "  requestWaitTime: 2\n"
                        + "  sendRefererHeader: true\n"
                        + "  threadCount: 2\n"
                        + "  userAgent: ua2";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        SpiderJob job = new SpiderJob();

        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(job.getParameters().getContext(), is(equalTo("context1")));
        assertThat(job.getParameters().getUrl(), is(equalTo("url1")));
        assertThat(job.getParameters().getMaxDuration(), is(equalTo(2)));
        assertThat(job.getParameters().getMaxDepth(), is(equalTo(2)));
        assertThat(job.getParameters().getMaxChildren(), is(equalTo(2)));
        assertThat(job.getParameters().getAcceptCookies(), is(equalTo(true)));
        assertThat(job.getParameters().getHandleODataParametersVisited(), is(equalTo(true)));
        assertThat(job.getParameters().getHandleParameters(), is(equalTo("ignore_completely")));
        assertThat(job.getParameters().getMaxParseSizeBytes(), is(equalTo(2)));
        assertThat(job.getParameters().getParseComments(), is(equalTo(true)));
        assertThat(job.getParameters().getParseGit(), is(equalTo(true)));
        assertThat(job.getParameters().getParseRobotsTxt(), is(equalTo(true)));
        assertThat(job.getParameters().getParseSitemapXml(), is(equalTo(true)));
        assertThat(job.getParameters().getParseSVNEntries(), is(equalTo(true)));
        assertThat(job.getParameters().getPostForm(), is(equalTo(true)));
        assertThat(job.getParameters().getProcessForm(), is(equalTo(true)));
        assertThat(job.getParameters().getRequestWaitTime(), is(equalTo(2)));
        assertThat(job.getParameters().getSendRefererHeader(), is(equalTo(true)));
        assertThat(job.getParameters().getThreadCount(), is(equalTo(2)));
        assertThat(job.getParameters().getUserAgent(), is(equalTo("ua2")));
    }

    @Test
    void shouldWarnOnDeprecatedFields() {
        String yamlStr =
                "parameters:\n"
                        + "  context: context1\n"
                        + "  failIfFoundUrlsLessThan: true\n"
                        + "  warnIfFoundUrlsLessThan: true";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        SpiderJob job = new SpiderJob();

        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!spider.automation.error.failIfUrlsLessThan.deprecated!")));
        assertThat(job.getParameters().getFailIfFoundUrlsLessThan(), is(equalTo(true)));
        assertThat(job.getParameters().getWarnIfFoundUrlsLessThan(), is(equalTo(true)));
    }

    @Test
    void shouldWarnOnUnknownFields() {
        String yamlStr = "parameters:\n" + "  context: context1\n" + "  unknown: true\n";
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        SpiderJob job = new SpiderJob();

        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
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
