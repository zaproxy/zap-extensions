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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.config.Property;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedMultigraph;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
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
import org.parosproxy.paros.extension.option.OptionsParamView;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientMapListener;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.client.internal.ElementLocator;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.DriverConfiguration;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ClientSpiderUnitTest extends TestUtils {

    private static final int PROXY_PORT = 8080;

    private List<String> logEvents;

    private ClientSpiderOptions clientOptions;
    private ClientMapListener mapListener;
    private ClientMap map;
    private String seedUrl;
    private CountDownLatch proxyCdl;
    private WebDriver wd;
    private ExtensionSelenium extSel;
    private ExtensionClientIntegration extClient;
    private Session session;
    private ExtensionNetwork network;
    private Server serverMock;

    private ClientSpider spider;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setUp() throws Exception {
        logEvents = registerLogEvents(Level.ERROR);

        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        OptionsParam optionsParam =
                mock(OptionsParam.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParamView viewParam =
                mock(OptionsParamView.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getOptionsParam()).willReturn(optionsParam);
        given(optionsParam.getViewParam()).willReturn(viewParam);
        given(viewParam.getMode()).willReturn(Control.Mode.standard.name());

        extClient =
                mock(
                        ExtensionClientIntegration.class,
                        withSettings().strictness(Strictness.LENIENT));
        extSel = mock(ExtensionSelenium.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionHistory history =
                mock(ExtensionHistory.class, withSettings().strictness(Strictness.LENIENT));
        when(extensionLoader.getExtension(ExtensionHistory.class)).thenReturn(history);
        when(extensionLoader.getExtension(ExtensionSelenium.class)).thenReturn(extSel);
        network = mock(ExtensionNetwork.class, withSettings().strictness(Strictness.LENIENT));
        when(extensionLoader.getExtension(ExtensionNetwork.class)).thenReturn(network);
        serverMock = mock(Server.class, withSettings().strictness(Strictness.LENIENT));
        proxyCdl = new CountDownLatch(1);
        given(serverMock.start(anyInt())).willReturn(PROXY_PORT);
        given(network.createHttpServer(any(HttpServerConfig.class))).willReturn(serverMock);

        wd = mock(withSettings().strictness(Strictness.LENIENT));
        WebElement wdElement =
                mock(WebElement.class, withSettings().strictness(Strictness.LENIENT));
        given(wdElement.isDisplayed()).willReturn(true);
        given(wdElement.isEnabled()).willReturn(true);
        given(wd.findElement(any())).willReturn(wdElement);
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

        when(extSel.getWebDriver(any(String.class), any(DriverConfiguration.class))).thenReturn(wd);
        given(extClient.getModel()).willReturn(model);
        session = mock(Session.class, withSettings().strictness(Strictness.LENIENT));
        given(model.getSession()).willReturn(session);
        map = mock(withSettings().strictness(Strictness.LENIENT));
        when(map.getGraph()).thenReturn(new DirectedMultigraph<>(DefaultEdge.class));
        clientOptions = new ClientSpiderOptions();
        clientOptions.load(new ZapXmlConfiguration());
        clientOptions.setThreadCount(1);
        clientOptions.setShutdownTimeInSecs(10);
        clientOptions.setPageLoadTimeInSecs(1);

        seedUrl = "https://www.example.com/";
        spider =
                new ClientSpider(
                        extClient,
                        map,
                        "",
                        seedUrl,
                        clientOptions,
                        ScanOptions.builder().setExternalControl(true).build(),
                        mock(ValueProvider.class),
                        1);
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
        verify(map, timeout(5000)).removeListener(clientMapListener());
    }

    private ClientMapListener clientMapListener() {
        if (mapListener == null) {
            ArgumentCaptor<ClientMapListener> captor = ArgumentCaptor.captor();
            verify(map, atLeastOnce()).addListener(captor.capture());
            mapListener = captor.getAllValues().get(0);
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
    void shouldOnlyRequestSessionScopeUrlsInProtectMode() throws Exception {
        // Given
        Control.getSingleton().setMode(Control.Mode.protect);
        given(session.isInScope(seedUrl)).willReturn(true);
        given(session.isInScope("https://www.example.com/inscope")).willReturn(true);
        given(session.isInScope("https://www.example.com/outofscope")).willReturn(false);
        given(session.isInScope("https://www.example.org/offsite")).willReturn(false);

        proxyCdl = new CountDownLatch(1);
        ClientSpider protectSpider =
                new ClientSpider(
                        extClient,
                        map,
                        "",
                        seedUrl,
                        clientOptions,
                        2,
                        null,
                        null,
                        false,
                        mock(ValueProvider.class));

        protectSpider.run();
        waitForProxy();

        ArgumentCaptor<ClientMapListener> listenerCaptor = ArgumentCaptor.captor();
        verify(map, atLeastOnce()).addListener(listenerCaptor.capture());
        ClientMapListener protectListener = listenerCaptor.getAllValues().get(1);

        // When
        protectListener.nodeAdded("https://www.example.com/inscope", 0, 0, PROXY_PORT);
        protectListener.nodeAdded("https://www.example.com/outofscope", 0, 0, PROXY_PORT);
        protectListener.nodeAdded("https://www.example.org/offsite", 0, 0, PROXY_PORT);
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());
        assertThat(argument.getAllValues(), contains(seedUrl, "https://www.example.com/inscope"));
    }

    @Test
    void shouldRequestInScopeUrlFoundDuringBrowserStartup() throws Exception {
        // Given
        clientMapListener();
        String urlFoundDuringStartup = "https://www.example.com/post-auth-page";
        CountDownLatch getWebDriverCdl = new CountDownLatch(1);
        when(extSel.getWebDriver(any(String.class), any(DriverConfiguration.class)))
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
    void shouldDeferUrlsFoundDuringCrawlUntilTasksComplete() throws Exception {
        // Given
        String deferredUrl = "https://www.example.com/deferred";
        CountDownLatch seedTaskRunningLatch = new CountDownLatch(1);
        CountDownLatch releaseTaskLatch = new CountDownLatch(1);

        doAnswer(
                        invocation -> {
                            proxyCdl.countDown();
                            if (seedUrl.equals(invocation.getArgument(0))) {
                                seedTaskRunningLatch.countDown();
                                releaseTaskLatch.await(2, TimeUnit.SECONDS);
                            }
                            return null;
                        })
                .when(wd)
                .get(any());

        // When / Then
        spider.run();
        seedTaskRunningLatch.await(2, TimeUnit.SECONDS);
        clientMapListener().nodeAdded(deferredUrl, 0, 0, PROXY_PORT);

        verify(wd, never()).get(deferredUrl);

        releaseTaskLatch.countDown();
        sleep();

        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());
        assertThat(argument.getAllValues(), contains(seedUrl, deferredUrl));
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
        sleep();
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
        ClientSideComponent component = linkComponent(seedUrl, "A", "Click");
        component.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), 'Click')]"));
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
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
        ClientSideComponent component = linkComponent(seedUrl, "A", "Click");
        component.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), 'Click')]"));
        clientMapListener().componentAdded(component, 1, 0, 1234);
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
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(), "area", "", url, "#", "", ClientSideComponent.Type.LINK, "", -1);
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
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
        ClientSideComponent component = linkComponent(url, "A", logoutText);
        component.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), 'logout')]"));
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, mode).findElement(By.xpath("//A[contains(text(), 'logout')]"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://www.example.com/a",
                "https://www.example.com/b",
                "HTTP://www.example.com/c",
                "HTTPS://www.example.com/d"
            })
    void shouldNotSkipClickForLinkComponentWithHref(String href) {
        // Given
        given(map.getNode(href, false, false)).willReturn(null);

        spider.run();
        waitForProxy();

        ClientSideComponent component = linkAComponent(seedUrl, href, "Unknown Link");

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd).findElement(any());
    }

    @Test
    void shouldSkipClickForLinkComponentForSamePage() {
        // Given
        spider.run();
        waitForProxy();
        ClientSideComponent component = linkAComponent(seedUrl, seedUrl, "Same Page Link");

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, never()).findElement(any());
    }

    @Test
    void shouldSkipClickForLinkComponentWithAlreadyHandledHref() {
        // Given
        String href = "https://www.example.com/queued-once";
        given(map.getNode(href, false, false)).willReturn(null);
        ClientSideComponent component = linkAComponent(seedUrl, href, "Same Link");

        spider.run();
        waitForProxy();

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd).findElement(any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"#fragment", "relative-path", "http-page", "https-page"})
    void shouldNotSkipClickForLinkComponentWithNonHttpHref(String href) {
        // Given
        spider.run();
        waitForProxy();
        ClientSideComponent component = linkAComponent(seedUrl, href, "Some Link");

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, times(2)).findElement(any());
    }

    @Test
    void shouldHandleComponentAddedWhenEnabledAndVisible() {
        // Given
        spider.run();
        waitForProxy();
        ClientSideComponent component =
                linkComponentWithInteractable(
                        seedUrl, "A", "Click", new InteractableState(true, true, false));

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd).findElement(any());
    }

    @Test
    void shouldHandleComponentAddedWhenInteractableIsNull() {
        // Given
        spider.run();
        waitForProxy();
        ClientSideComponent component = linkComponent(seedUrl, "A", "Click");
        component.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), 'Click')]"));

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd).findElement(any());
    }

    static Stream<Arguments> notInteractableStates() {
        return Stream.of(
                arguments(new InteractableState(false, true, false)),
                arguments(new InteractableState(true, false, false)),
                arguments(new InteractableState(false, false, false)));
    }

    @ParameterizedTest
    @MethodSource("notInteractableStates")
    void shouldIgnoreComponentAddedWhenNotInteractable(InteractableState interactable) {
        // Given
        spider.run();
        waitForProxy();
        ClientSideComponent component =
                linkComponentWithInteractable(seedUrl, "A", "Click", interactable);

        // When
        clientMapListener().componentAdded(component, 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, never()).findElement(any());
    }

    @ParameterizedTest
    @CsvSource({
        "https://www.example.org/new-path, https://www.example.org/new-path",
        "/relative-path, https://www.example.com/relative-path",
        "/path with spaces, https://www.example.com/path%20with%20spaces",
        "  /path-trim-spaces  , https://www.example.com/path-trim-spaces"
    })
    void shouldTrackRedirectsAtNetworkLevel(String location, String expectedRedirectUrl)
            throws Exception {
        // Given
        HttpMessageHandlerSetup setup = setUpRedirect(location);

        // When
        setup.handler().handleMessage(setup.ctx(), setup.redirectMessage());

        // Then
        verify(map).getOrAddNode("https://www.example.com/original", true, false);
        verify(map).getOrAddNode(expectedRedirectUrl, false, false);
        verify(map).setRedirect("https://www.example.com/original", expectedRedirectUrl);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"  ", ""})
    void shouldIgnoreInvalidRedirectsAtNetworkLevel(String location) throws Exception {
        // Given
        HttpMessageHandlerSetup setup = setUpRedirect(location);

        // When
        setup.handler().handleMessage(setup.ctx(), setup.redirectMessage());

        // Then
        verify(map, never()).setRedirect(anyString(), anyString());
    }

    private HttpMessageHandlerSetup setUpRedirect(String location) throws Exception {
        HttpMessage redirectMessage = new HttpMessage();
        redirectMessage
                .getRequestHeader()
                .setURI(new URI("https://www.example.com/original", true));
        redirectMessage.setResponseHeader("HTTP/1.1 302 Found");
        redirectMessage.getResponseHeader().setHeader(HttpFieldsNames.LOCATION, location);

        ArgumentCaptor<HttpServerConfig> configCaptor = ArgumentCaptor.captor();
        given(network.createHttpServer(configCaptor.capture())).willReturn(serverMock);
        spider.run();
        waitForProxy();

        HttpMessageHandler handler = configCaptor.getValue().getHttpMessageHandler();
        HttpMessageHandlerContext ctx = mock(HttpMessageHandlerContext.class);
        given(ctx.isFromClient()).willReturn(false);

        return new HttpMessageHandlerSetup(handler, ctx, redirectMessage);
    }

    private record HttpMessageHandlerSetup(
            HttpMessageHandler handler,
            HttpMessageHandlerContext ctx,
            HttpMessage redirectMessage) {}

    @Test
    void shouldFinishImmediatelyWhenExistingOnlyAndMapIsEmpty() {
        // Given
        ClientNode root = mockRootNode();
        given(map.getRoot()).willReturn(root);
        useExistingOnlySpider();

        // When
        spider.run();

        // Then - spider completes without hanging
        verify(wd, timeout(5000).times(0)).get(anyString());
        assertThat(spider.isStopped(), is(true));
    }

    @Test
    void shouldVisitVisitedAndContentLoadedNodesWhenExistingOnly() {
        // Given
        String visitedUrl = "https://www.example.com/visited";
        String loadedUrl = "https://www.example.com/loaded";
        String unvisitedUrl = "https://www.example.com/unvisited";

        ClientNode root =
                mockRootNode(
                        mockClientNode(visitedUrl, false, true, false),
                        mockClientNode(loadedUrl, false, false, true),
                        mockClientNode(unvisitedUrl, false, false, false));
        given(map.getRoot()).willReturn(root);
        useExistingOnlySpider();

        // When
        spider.run();
        sleep();

        // Then
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);
        verify(wd, atLeastOnce()).get(argument.capture());
        assertThat(argument.getAllValues(), contains(visitedUrl, loadedUrl));
    }

    @Test
    void shouldNotFollowNewUrlsDiscoveredDuringExistingOnlyScan() {
        // Given
        String existingUrl = "https://www.example.com/existing";
        String newUrl = "https://www.example.com/new";

        ClientNode root = mockRootNode(mockClientNode(existingUrl, false, true, false));
        given(map.getRoot()).willReturn(root);
        useExistingOnlySpider();
        spider.run();
        waitForProxy();

        // When
        clientMapListener().nodeAdded(newUrl, 0, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, never()).get(newUrl);
    }

    @Test
    void shouldNotProcessComponentsDiscoveredDuringExistingOnlyScan() {
        // Given
        String existingUrl = "https://www.example.com/existing";

        ClientNode root = mockRootNode(mockClientNode(existingUrl, false, true, false));
        given(map.getRoot()).willReturn(root);
        useExistingOnlySpider();
        spider.run();
        waitForProxy();

        // When
        clientMapListener()
                .componentAdded(
                        linkAComponent(seedUrl, existingUrl, "Some Link"), 1, 0, PROXY_PORT);
        sleep();

        // Then
        verify(wd, never()).findElement(any());
    }

    @Test
    void shouldSubmitKnownFormComponentsWhenExistingOnly() {
        // Given
        String pageUrl = "https://www.example.com/form-page";

        ClientNode pageNode = mockClientNode(pageUrl, false, true, false);
        ClientSideComponent form = mockFormComponent(0);
        ClientSideDetails pageDetails = pageNode.getUserObject();
        given(pageDetails.getComponents()).willReturn(Set.of(form));

        ClientNode root = mockRootNode(pageNode);
        given(map.getRoot()).willReturn(root);
        useExistingOnlySpider();

        // When
        spider.run();
        sleep();

        // Then - FollowGraph navigates to the page, then SubmitForm finds and submits the form
        verify(wd).findElement(By.xpath("//FORM[1]"));
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

    private ClientSideComponent linkAComponent(String parentUrl, String href, String text) {
        ClientSideComponent component =
                new ClientSideComponent(
                        Map.of(),
                        "A",
                        "",
                        parentUrl,
                        href,
                        text,
                        ClientSideComponent.Type.LINK,
                        "",
                        -1);
        component.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), 'logout')]"));
        return component;
    }

    private static ClientSideComponent linkComponent(String url, String tagName, String text) {
        return new ClientSideComponent(
                Map.of(), tagName, "", url, null, text, ClientSideComponent.Type.LINK, "", -1);
    }

    private static ClientSideComponent linkComponentWithInteractable(
            String url, String tagName, String text, InteractableState interactable) {
        ClientSideComponent c = linkComponent(url, tagName, text);
        c.setInteractable(interactable);
        c.setElementLocator(new ElementLocator("xpath", "//A[contains(text(), '" + text + "')]"));
        return c;
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

    private void useExistingOnlySpider() {
        clearInvocations(map);
        mapListener = null;
        spider =
                new ClientSpider(
                        extClient,
                        map,
                        "",
                        seedUrl,
                        clientOptions,
                        ScanOptions.builder()
                                .setExistingOnly(true)
                                .setExternalControl(true)
                                .build(),
                        mock(ValueProvider.class),
                        1);
    }

    private static ClientNode mockRootNode(ClientNode... children) {
        ClientNode root = mock(withSettings().strictness(Strictness.LENIENT));
        given(root.isRoot()).willReturn(true);
        given(root.getChildCount()).willReturn(children.length);
        for (int i = 0; i < children.length; i++) {
            given(root.getChildAt(i)).willReturn(children[i]);
        }
        return root;
    }

    private static ClientSideComponent mockFormComponent(int formId) {
        ClientSideComponent component = mock(withSettings().strictness(Strictness.LENIENT));
        given(component.getBy()).willReturn(By.xpath("//FORM[" + (formId + 1) + "]"));
        given(component.getTagName()).willReturn("FORM");
        return component;
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
