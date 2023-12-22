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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriver.Options;
import org.openqa.selenium.WebDriver.Timeouts;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ClientMap;
import org.zaproxy.addon.client.ClientNode;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ClientSideDetails;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ClientSpiderUnitTest {

    private ExtensionSelenium extSel;
    private ClientOptions clientOptions;
    private ClientMap map;
    private WebDriver wd;

    @BeforeEach
    void setUp() {
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
        extSel = mock(ExtensionSelenium.class);
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class))
                .thenReturn(extSel);
        wd = mock(WebDriver.class);
        when(extSel.getProxiedBrowser(any(String.class), any(String.class))).thenReturn(wd);
        Session session = mock(Session.class);
        map = new ClientMap(new ClientNode(new ClientSideDetails("Root", ""), session));
        clientOptions = new ClientOptions();
        clientOptions.load(new ZapXmlConfiguration());
        clientOptions.setThreadCount(1);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(map);
    }

    @Test
    void shouldRequestInScopeUrls() {
        // Given
        ClientSpider spider = new ClientSpider("https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.start();
        map.getOrAddNode("https://www.example.com/test#1", false, false);
        // Note the ".org" - this should not be requested
        map.getOrAddNode("https://www.example.org/test#2", false, false);
        map.getOrAddNode("https://www.example.com/test#3", false, false);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }
        spider.stop();

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
    void shouldIgnoreRequestAfterStopped() {
        // Given
        ClientSpider spider = new ClientSpider("https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);

        // When
        spider.start();
        spider.stop();
        map.getOrAddNode("https://www.example.com/test#1", false, false);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // Ignore
        }

        // Then
        verify(wd, never()).get(any());
    }

    @Test
    void shouldStartPauseResumeStopSpider() {
        // Given
        ClientSpider spider = new ClientSpider("https://www.example.com", clientOptions, 1);
        SpiderStatus statusPostStart;
        SpiderStatus statusPostPause;
        SpiderStatus statusPostResume;
        SpiderStatus statusPostStop;

        // When
        spider.start();
        statusPostStart = new SpiderStatus(spider);
        spider.pause();
        statusPostPause = new SpiderStatus(spider);
        spider.resume();
        statusPostResume = new SpiderStatus(spider);
        spider.stop();
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
        ClientSpider spider = new ClientSpider("https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.start();
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
        spider.stop();
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
        ClientSpider spider = new ClientSpider("https://www.example.com/", clientOptions, 1);
        Options options = mock(Options.class);
        Timeouts timeouts = mock(Timeouts.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        when(wd.manage()).thenReturn(options);
        when(options.timeouts()).thenReturn(timeouts);
        ArgumentCaptor<String> argument = ArgumentCaptor.forClass(String.class);

        // When
        spider.start();
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
        spider.stop();
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
}
