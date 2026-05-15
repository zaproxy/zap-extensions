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
package org.zaproxy.addon.client.spider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.mockito.verification.VerificationMode;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Options;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientMapListener;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ClientSpiderUnitTest extends TestUtils {

    private static final int PROXY_PORT = 8080;

    private List<String> logEvents;

    private ClientOptions clientOptions;
    private ClientMapListener mapListener;
    private ClientMap map;
    private String seedUrl;
    private CountDownLatch proxyCdl;
    private WebDriver wd;
    private ExtensionSelenium extSel;

    private ClientSpider spider;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() throws Exception {
        logEvents = registerLogEvents(Level.ERROR);

        Model model = mock(Model.class);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(model, extensionLoader);
        ExtensionClientIntegration extClient = mock(ExtensionClientIntegration.class);
        extSel = mock(ExtensionSelenium.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionHistory history = mock(ExtensionHistory.class);
        when(extensionLoader.getExtension(ExtensionHistory.class)).thenReturn(history);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSel);
        ExtensionNetwork network =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        when(extensionLoader.getExtension(ExtensionNetwork.class)).thenReturn(network);
        Server serverMock = mock(Server.class, withSettings().strictness(Strictness.LENIENT));
        proxyCdl = new CountDownLatch(1);
        given(serverMock.start(anyInt())).willReturn(PROXY_PORT);
        given(network.createHttpServer(any(HttpServerConfig.class))).willReturn(serverMock);

        wd = mock(withSettings().strictness(Strictness.LENIENT));
        given(wd.findElement(any())).willReturn(mock(WebElement.class));
        Options options = mock(withSettings().strictness(Strictness.LENIENT));
        doAnswer(
                        answer -> {
                            proxyCdl.countDown();
                            return null;
                        })
                .when(wd)
                .get(any());
        when(wd.manage()).thenReturn(options);
        when(options.timeouts())
                .thenReturn(
                        mock(
                                withSettings()
                                        .defaultAnswer(CALLS_REAL_METHODS)
                                        .strictness(Strictness.LENIENT)));

        when(extSel.getWebDriver(anyInt(), any(String.class), any(String.class), anyInt()))
                .thenReturn(wd);
        given(extClient.getModel()).willReturn(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        map = mock();
        clientOptions = new ClientOptions();
        clientOptions.load(new ZapXmlConfiguration());
        clientOptions.setThreadCount(1);
        clientOptions.setShutdownTimeInSecs(10);

        seedUrl = "https://www.example.com/";
        spider =
                new ClientSpider(
                        extClient,
                        map,
                        "",
                        seedUrl,
                        clientOptions,
                        1,
                        null,
                        null,
                        false,
                        mock(ValueProvider.class));
    }

    @AfterEach
    void tearDown() throws Exception {
        assertThat(logEvents, is(empty()));

        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void shouldAddListenerToClientMapOnCreation() {
        verify(map).addListener(any(ClientMapListener.class));
    }

    @Test
    void shouldRemoveListenerFromClientMapWhenFinished() {
        // Given
        clientMapListener();

        // When
        spider.run();
        spider.stopScan();

        // Then
        verify(map).removeListener(clientMapListener());
    }

    private ClientMapListener clientMapListener() {
        if (mapListener == null) {
            ArgumentCaptor<ClientMapListener> captor = ArgumentCaptor.captor();
            verify(map).addListener(captor.capture());
            mapListener = captor.getValue();
        }
        return mapListener;
    }

    @Test
    void shouldRequestInScopeUrls() {
        // Given
        spider.run();
        waitForProxy();

        // When
        clientMapListener().nodeAdded("https://www.example.com/test", 0, 0, PROXY_PORT);
        // Note the ".org" - this should not be requested
        clientMapListener().nodeAdded("https://www.example.org/test", 0, 0, PROXY_PORT);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(
                argument.getAllValues(),
                contains("https://www.example.com/", "https://www.example.com/test"));
    }

    @Test
    void shouldRequestInScopeUrlFoundDuringBrowserStartup() throws Exception {
        // Given
        clientMapListener();
        String urlFoundDuringStartup = "https://www.example.com/post-auth-page";
        CountDownLatch getWebDriverCdl = new CountDownLatch(1);
        when(extSel.getWebDriver(anyInt(), any(String.class), any(String.class), anyInt()))
                .thenAnswer(
                        invocation -> {
                            mapListener.nodeAdded(urlFoundDuringStartup, 0, 0, PROXY_PORT);
                            getWebDriverCdl.countDown();
                            return wd;
                        });

        // When
        spider.run();
        getWebDriverCdl.await(2, TimeUnit.SECONDS);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(argument.getAllValues(), contains(seedUrl, urlFoundDuringStartup));
    }

    @Test
    void shouldIgnoreRequestAfterStopped() throws Exception {
        // Given
        CountDownLatch cdl = new CountDownLatch(1);
        String urlAfterStop = "https://www.example.com/test#1";
        doAnswer(
                        invocation -> {
                            spider.stopScan();
                            map.getOrAddNode(urlAfterStop, false, false);
                            cdl.countDown();
                            return null;
                        })
                .when(wd)
                .get(seedUrl);

        // When
        spider.run();
        // and stopped on URL access

        // Then
        cdl.await(2, TimeUnit.SECONDS);
        assertThat(spider.isStopped(), is(true));
        verify(wd, never()).get(urlAfterStop);
    }

    @Test
    void shouldStartPauseResumeStopSpider() {
        // Given
        SpiderStatus statusPostStart;
        SpiderStatus statusPostPause;
        SpiderStatus statusPostResume;
        SpiderStatus statusPostStop;

        // When
        spider.run();
        statusPostStart = new SpiderStatus(spider);
        spider.pauseScan();
        statusPostPause = new SpiderStatus(spider);
        spider.resumeScan();
        statusPostResume = new SpiderStatus(spider);
        spider.stopScan();
        statusPostStop = new SpiderStatus(spider);

        // Then
        assertThat(statusPostStart.isRunning(), is(true));
        assertThat(statusPostStart.isPaused(), is(false));
        assertThat(statusPostStart.isStopped(), is(false));

        assertThat(statusPostPause.isRunning(), is(true));
        assertThat(statusPostPause.isPaused(), is(true));
        assertThat(statusPostPause.isStopped(), is(false));

        assertThat(statusPostResume.isRunning(), is(true));
        assertThat(statusPostResume.isPaused(), is(false));
        assertThat(statusPostResume.isStopped(), is(false));

        assertThat(statusPostStop.isRunning(), is(false));
        assertThat(statusPostStop.isPaused(), is(false));
        assertThat(statusPostStop.isStopped(), is(true));
    }

    @Test
    void shouldIgnoreUrlsNotFromProxy() {
        // Given
        spider.run();
        waitForProxy();

        // When
        clientMapListener().nodeAdded("https://www.example.com/notfromproxy", 0, 0, 1234);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(argument.getAllValues(), contains(seedUrl));
    }

    @Test
    void shouldIgnoreUrlsTooDeep() {
        // Given
        clientOptions.setMaxDepth(5);
        spider.run();
        waitForProxy();

        // When
        clientMapListener().nodeAdded("https://www.example.com/l1", 2, 0, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l1/l2", 3, 0, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l1/l2/l3", 4, 0, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l1/l2/l3/l4", 5, 0, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l1/l2/l3/l4/l5", 6, 0, PROXY_PORT);
        clientMapListener()
                .nodeAdded("https://www.example.com/l1/l2/l3/l4/l5/l6", 7, 0, PROXY_PORT);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(
                argument.getAllValues(),
                contains(
                        seedUrl,
                        "https://www.example.com/l1",
                        "https://www.example.com/l1/l2",
                        "https://www.example.com/l1/l2/l3",
                        "https://www.example.com/l1/l2/l3/l4"));
    }

    @Test
    void shouldIgnoreUrlsTooWide() {
        // Given
        clientOptions.setMaxChildren(4);
        spider.run();
        waitForProxy();

        // When
        clientMapListener().nodeAdded("https://www.example.com/l1", 0, 1, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l2", 0, 2, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l3", 0, 3, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l4", 0, 4, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l5", 0, 5, PROXY_PORT);
        clientMapListener().nodeAdded("https://www.example.com/l6", 0, 6, PROXY_PORT);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(
                argument.getAllValues(),
                contains(
                        seedUrl,
                        "https://www.example.com/l1",
                        "https://www.example.com/l2",
                        "https://www.example.com/l3",
                        "https://www.example.com/l4"));
    }

    @Test
    void shouldVisitKnownUnvisitedUrls() {
        // Given
        ClientNode seedNode = mockClientNode(seedUrl, false, false, false);
        given(map.getNode(seedUrl, false, false)).willReturn(seedNode);

        ClientNode mainNode = mockClientNode("https://www.example.com", false, false, false);
        given(seedNode.getParent()).willReturn(mainNode);
        int childCount = -1;
        mockChild(mainNode, ++childCount, seedNode);
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/test", false, false, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/test#", false, false, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/test#1", false, false, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/test#2", false, false, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/visited", false, true, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/loaded", false, false, true));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.com/storage", true, false, false));
        mockChild(
                mainNode,
                ++childCount,
                mockClientNode("https://www.example.org/outofscope", false, false, false));
        given(mainNode.getChildCount()).willReturn(childCount + 1);

        // When
        spider.run();
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());

        assertThat(
                argument.getAllValues(),
                contains(
                        seedUrl,
                        "https://www.example.com",
                        "https://www.example.com/",
                        "https://www.example.com/test",
                        "https://www.example.com/test#",
                        "https://www.example.com/test#1",
                        "https://www.example.com/test#2"));
    }

    @Test
    void shouldHandleComponentAdded() {
        // Given
        spider.run();
        waitForProxy();

        // When
        clientMapListener()
                .componentAdded(
                        Map.of(
                                ClientMap.URL_KEY,
                                seedUrl,
                                "tagName",
                                "A",
                                "text",
                                "Click",
                                "depth",
                                "1"),
                        PROXY_PORT);
        sleep();

        // Then
        verify(wd).findElement(By.xpath("//A[contains(text(), 'Click')]"));
    }

    @Test
    void shouldNotHandleComponentAddedIfNotFromProxy() {
        // Given
        spider.run();
        waitForProxy();

        // When
        clientMapListener()
                .componentAdded(
                        Map.of(
                                ClientMap.URL_KEY,
                                seedUrl,
                                "tagName",
                                "A",
                                "text",
                                "Click",
                                "depth",
                                "1"),
                        1234);
        sleep();

        // Then
        verify(wd, never()).findElement(any());
    }

    @Test
    void shouldHandleComponentHrefWithoutHostname() {
        // Given
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        spider.run();
        waitForProxy();
        String url = "https://www.example.com/new";
        clientMapListener().nodeAdded(url, 0, 1, PROXY_PORT);

        // When
        clientMapListener()
                .componentAdded(
                        Map.of(
                                ClientMap.URL_KEY,
                                url,
                                "tagName",
                                "area",
                                "href",
                                "#",
                                "depth",
                                "1"),
                        PROXY_PORT);
        sleep();

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(values, contains(seedUrl, "https://www.example.com/new"));
    }

    static Stream<Arguments> logoutAvoidanceArgs() {
        return Stream.of(arguments(true, never()), arguments(false, times(1)));
    }

    @ParameterizedTest
    @MethodSource("logoutAvoidanceArgs")
    void shouldHandleLogoutElementsBasedOnLogoutAvoidance(
            boolean logoutAvoidance, VerificationMode mode) {
        // Given
        String logoutText = "logout";
        clientOptions.setLogoutAvoidance(logoutAvoidance);
        String url = "https://www.example.com/";

        spider.run();
        waitForProxy();

        // When
        clientMapListener()
                .componentAdded(
                        Map.of(
                                ClientMap.URL_KEY,
                                url,
                                "tagName",
                                "A",
                                "text",
                                logoutText,
                                "depth",
                                "1"),
                        PROXY_PORT);
        sleep();

        // Then
        verify(wd, mode).findElement(By.xpath("//A[contains(text(), 'logout')]"));
    }

    class SpiderStatus {
        private boolean running;
        private boolean paused;
        private boolean stopped;

        SpiderStatus(ClientSpider cs) {
            this.running = cs.isRunning();
            this.paused = cs.isPaused();
            this.stopped = cs.isStopped();
        }

        public boolean isRunning() {
            return running;
        }

        public boolean isPaused() {
            return paused;
        }

        public boolean isStopped() {
            return stopped;
        }
    }

    private static ClientNode mockClientNode(
            String url, boolean storage, boolean visited, boolean contentLoaded) {
        ClientNode node = mock(withSettings().strictness(Strictness.LENIENT));
        given(node.isStorage()).willReturn(storage);

        ClientSideDetails details = mock(withSettings().strictness(Strictness.LENIENT));
        given(node.getUserObject()).willReturn(details);

        given(details.getUrl()).willReturn(url);
        given(details.isStorage()).willReturn(storage);
        given(details.isVisited()).willReturn(visited);
        given(details.isContentLoaded()).willReturn(contentLoaded);

        return node;
    }

    private static void mockChild(ClientNode parent, int index, ClientNode child) {
        given(parent.getChildAt(index)).willReturn(child);
    }

    private static void sleep() {
        try {
            Thread.sleep(750);
        } catch (InterruptedException e) {
            // Ignore
        }
    }

    private void waitForProxy() {
        try {
            if (!proxyCdl.await(1, TimeUnit.SECONDS)) {
                throw new RuntimeException("Proxy not started in time.");
            }
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<String> registerLogEvents(Level level) {
        List<String> logEvents = new ArrayList<>();
        TestLogAppender logAppender = new TestLogAppender(logEvents::add);
        LoggerContext context = LoggerContext.getContext();
        LoggerConfig rootLoggerconfig = context.getConfiguration().getRootLogger();
        rootLoggerconfig.getAppenders().values().forEach(context.getRootLogger()::removeAppender);
        rootLoggerconfig.addAppender(logAppender, null, null);
        rootLoggerconfig.setLevel(level);
        context.updateLoggers();
        return logEvents;
    }

    private static class TestLogAppender extends AbstractAppender {

        private static final Property[] NO_PROPERTIES = {};

        private final Consumer<String> logConsumer;

        public TestLogAppender(Consumer<String> logConsumer) {
            this("%m%n", logConsumer);
        }

        public TestLogAppender(String pattern, Consumer<String> logConsumer) {
            super(
                    "TestLogAppender",
                    null,
                    PatternLayout.newBuilder()
                            .withDisableAnsi(true)
                            .withCharset(StandardCharsets.UTF_8)
                            .withPattern(pattern)
                            .build(),
                    true,
                    NO_PROPERTIES);
            this.logConsumer = logConsumer;
            start();
        }

        @Override
        public void append(LogEvent event) {
            logConsumer.accept(((StringLayout) getLayout()).toSerializable(event));
        }
    }
}
