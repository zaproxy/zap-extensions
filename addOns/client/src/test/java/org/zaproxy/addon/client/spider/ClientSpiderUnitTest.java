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
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Options;
import org.openqa.selenium.WebDriver.Timeouts;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ClientSpiderUnitTest extends TestUtils {

    private ExtensionSelenium extSel;
    private ExtensionHistory history;
    private ExtensionClientIntegration extClient;
    private ClientOptions clientOptions;
    private ClientMap map;
    private WebDriver wd;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() {
        Model model = mock(Model.class);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(model, extensionLoader);
        extClient = mock(ExtensionClientIntegration.class);
        extSel = mock(ExtensionSelenium.class, withSettings().strictness(Strictness.LENIENT));
        history = mock(ExtensionHistory.class);
        when(extensionLoader.getExtension(ExtensionHistory.class)).thenReturn(history);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSel);
        ExtensionNetwork network =
                mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        when(extensionLoader.getExtension(ExtensionNetwork.class)).thenReturn(network);
        given(network.createHttpServer(any(HttpServerConfig.class))).willReturn(mock(Server.class));
        wd = mock(WebDriver.class);
        when(extSel.getWebDriver(anyInt(), any(String.class), any(String.class), anyInt()))
                .thenReturn(wd);
        given(extClient.getModel()).willReturn(model);
        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);
        map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), session));
        clientOptions = new ClientOptions();
        clientOptions.load(new ZapXmlConfiguration());
        clientOptions.setThreadCount(1);
    }

    @AfterEach
    void tearDown() throws Exception {
        ZAP.getEventBus().unregisterPublisher(map);
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void shouldRequestInScopeUrls() {
        // Given
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.run();
        map.getOrAddNode("https://www.example.com/test#1", false, false);
        // Note the ".org" - this should not be requested
        map.getOrAddNode("https://www.example.org/test#2", false, false);
        map.getOrAddNode("https://www.example.com/test#3", false, false);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stopScan();

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(
                values,
                contains(
                        "https://www.example.com/",
                        "https://www.example.com/test#1",
                        "https://www.example.com/test#3"));
    }

    @Test
    void shouldIgnoreRequestAfterStopped() throws Exception {
        // Given
        CountDownLatch cdl = new CountDownLatch(1);
        String seedUrl = "https://www.example.com/";
        ClientSpider spider = new ClientSpider(extClient, "", seedUrl, clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
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
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com", clientOptions, 1);
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
    void shouldIgnoreUrlsTooDeep() {
        // Given
        clientOptions.setMaxDepth(5);
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.run();
        map.getOrAddNode("https://www.example.com/l1", false, false);
        map.getOrAddNode("https://www.example.com/l1/l2", false, false);
        map.getOrAddNode("https://www.example.com/l1/l2/l3", false, false);
        map.getOrAddNode("https://www.example.com/l1/l2/l3/l4", false, false);
        map.getOrAddNode("https://www.example.com/l1/l2/l3/l4/l5", false, false);
        map.getOrAddNode("https://www.example.com/l1/l2/l3/l4/l5/l6", false, false);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stopScan();
        ClientNode l6Node = map.getNode("https://www.example.com/l1/l2/l3/l4/l5/l6", false, false);

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(
                values,
                contains(
                        "https://www.example.com/",
                        "https://www.example.com/l1",
                        "https://www.example.com/l1/l2",
                        "https://www.example.com/l1/l2/l3",
                        "https://www.example.com/l1/l2/l3/l4"));
        assertThat(l6Node, is(notNullValue()));
    }

    @Test
    void shouldIgnoreUrlsTooWide() {
        // Given
        clientOptions.setMaxChildren(4);
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.run();
        map.getOrAddNode("https://www.example.com/l1", false, false);
        map.getOrAddNode("https://www.example.com/l2", false, false);
        map.getOrAddNode("https://www.example.com/l3", false, false);
        map.getOrAddNode("https://www.example.com/l4", false, false);
        map.getOrAddNode("https://www.example.com/l5", false, false);
        map.getOrAddNode("https://www.example.com/l6", false, false);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stopScan();
        ClientNode l6Node = map.getNode("https://www.example.com/l6", false, false);

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(
                values,
                contains(
                        "https://www.example.com/",
                        "https://www.example.com/l1",
                        "https://www.example.com/l2",
                        "https://www.example.com/l3",
                        "https://www.example.com/l4"));
        assertThat(l6Node, is(notNullValue()));
    }

    @Test
    void shouldVisitKnownUnvisitedUrls() {
        // Given
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        ClientNode exampleTopNode = getClientNode("https://www.example.com", false);
        ClientNode exampleSlashNode = getClientNode("https://www.example.com/", false);
        ClientNode exampleTest1Node = getClientNode("https://www.example.com/test#1", false);
        ClientNode exampleTest2Node = getClientNode("https://www.example.com/test#2", false);
        ClientNode exampleVisitedNode = getClientNode("https://www.example.com/visited", true);
        exampleTopNode.add(exampleSlashNode);
        exampleTopNode.add(exampleTest1Node);
        exampleTopNode.add(exampleTest2Node);
        exampleTopNode.add(exampleVisitedNode);
        when(extClient.getClientNode("https://www.example.com/", false, false))
                .thenReturn(exampleSlashNode);

        // When
        spider.run();

        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stopScan();

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(
                values,
                contains(
                        "https://www.example.com/",
                        "https://www.example.com",
                        "https://www.example.com/",
                        "https://www.example.com/test#1",
                        "https://www.example.com/test#2"));
    }

    @Test
    void shouldHandleComponentHrefWithoutHostname() {
        // Given
        List<String> logEvents = registerLogEvents(Level.ERROR);
        ClientSpider spider =
                new ClientSpider(extClient, "", "https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        spider.run();
        String url = "https://www.example.com/new";
        ClientNode node = map.getOrAddNode(url, false, false);
        // When
        map.addComponentToNode(
                node,
                new ClientSideComponent(
                        Map.of(ClientMap.URL_KEY, url, "tagName", "area", "href", "#"),
                        "area",
                        null,
                        url,
                        "#",
                        null,
                        ClientSideComponent.Type.LINK,
                        null,
                        -1));
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stopScan();

        // Then
        verify(wd, atLeastOnce()).get(argument.capture());

        List<String> values = argument.getAllValues();
        assertThat(values, contains("https://www.example.com/", "https://www.example.com/new"));
        assertThat(logEvents, is(empty()));
    }

    private static ClientNode getClientNode(String url, boolean visited) {
        return new ClientNode(new ClientSideDetails(url, url, visited, false), false);
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
