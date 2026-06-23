/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ClientSpiderOptions}. */
class ClientSpiderOptionsUnitTest extends TestUtils {

    private ClientSpiderOptions options;
    private ZapXmlConfiguration config;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionClientIntegration());
        options = new ClientSpiderOptions();
        config = new ZapXmlConfiguration();
    }

    @Test
    void shouldUseTheRightDefaults() {
        // Given / When
        options.load(config);
        // Then
        assertThat(options.getBrowserId(), is(ClientSpiderOptions.DEFAULT_BROWSER_ID));
        assertThat(
                options.getInitialLoadTimeInSecs(),
                is(ClientSpiderOptions.DEFAULT_INITIAL_LOAD_TIME));
        assertThat(options.getPageLoadTimeInSecs(), is(ClientSpiderOptions.DEFAULT_PAGE_LOAD_TIME));
        assertThat(options.getShutdownTimeInSecs(), is(ClientSpiderOptions.DEFAULT_SHUTDOWN_TIME));
        assertThat(options.getMaxDepth(), is(ClientSpiderOptions.DEFAULT_MAX_DEPTH));
        assertThat(options.getMaxChildren(), is(0));
        assertThat(options.getMaxDuration(), is(0));
        assertThat(options.getThreadCount(), is(ClientSpiderOptions.getDefaultThreadCount()));
        assertThat(options.isLogoutAvoidance(), is(ClientSpiderOptions.DEFAULT_LOGOUT_AVOIDANCE));
        assertThat(
                options.getActionWaitTimeInSecs(),
                is(ClientSpiderOptions.DEFAULT_ACTION_WAIT_TIME));
        assertThat(options.getScopeCheck(), is(ClientSpiderOptions.ScopeCheck.getDefault()));
    }

    @Test
    void shouldUseTheRightValues() {
        // Given
        config.setProperty("client.spider.browserId", "chrome");
        config.setProperty("client.spider.initialLoadTime", 1);
        config.setProperty("client.spider.maxChildren", 2);
        config.setProperty("client.spider.maxDepth", 3);
        config.setProperty("client.spider.maxDuration", 4);
        config.setProperty("client.spider.pageLoadTime", 5);
        config.setProperty("client.spider.shutdownTime", 6);
        config.setProperty("client.spider.threads", 7);
        config.setProperty(
                "client.spider.logoutAvoidance", !ClientSpiderOptions.DEFAULT_LOGOUT_AVOIDANCE);
        config.setProperty("client.spider.actionWaitTime", 9);
        // When
        options.load(config);
        // Then
        assertThat(options.getBrowserId(), is("chrome"));
        assertThat(options.getInitialLoadTimeInSecs(), is(1));
        assertThat(options.getMaxChildren(), is(2));
        assertThat(options.getMaxDepth(), is(3));
        assertThat(options.getMaxDuration(), is(4));
        assertThat(options.getPageLoadTimeInSecs(), is(5));
        assertThat(options.getShutdownTimeInSecs(), is(6));
        assertThat(options.getThreadCount(), is(7));
        assertThat(options.isLogoutAvoidance(), is(!ClientSpiderOptions.DEFAULT_LOGOUT_AVOIDANCE));
        assertThat(options.getActionWaitTimeInSecs(), is(9));
    }

    @Test
    void shouldMigrateFromOriginalClientBaseKey() {
        // Given - config with original "client" spider keys (before the split)
        config.addProperty("client.browserId", "firefox-headless");
        config.addProperty("client.threads", 4);
        config.addProperty("client.maxDepth", 10);
        config.addProperty("client.logoutAvoidance", false);
        config.addProperty("client.pscanEnabled", false);
        // When
        options.load(config);
        // Then - spider values migrated to "client.spider" keys
        assertThat(options.getBrowserId(), is("firefox-headless"));
        assertThat(options.getThreadCount(), is(4));
        assertThat(options.getMaxDepth(), is(10));
        assertThat(options.isLogoutAvoidance(), is(false));
        // And old spider keys removed
        assertThat(config.getProperty("client.browserId"), is(nullValue()));
        assertThat(config.getProperty("client.threads"), is(nullValue()));
        // Pscan key left untouched
        assertThat(config.getProperty("client.pscanEnabled"), is(false));
    }

    @Test
    void shouldSetOptions() {
        // Given
        options.load(config);
        // When
        options.setBrowserId("firefox-headless");
        options.setInitialLoadTimeInSecs(4);
        options.setMaxChildren(100);
        options.setMaxDepth(10);
        options.setMaxDuration(100);
        options.setPageLoadTimeInSecs(3);
        options.setShutdownTimeInSecs(10);
        options.setThreadCount(32);
        options.setLogoutAvoidance(false);
        options.setActionWaitTimeInSecs(2);
        // Then
        assertThat(config.getProperty("client.spider.browserId"), is("firefox-headless"));
        assertThat(config.getProperty("client.spider.initialLoadTime"), is(4));
        assertThat(config.getProperty("client.spider.maxChildren"), is(100));
        assertThat(config.getProperty("client.spider.maxDepth"), is(10));
        assertThat(config.getProperty("client.spider.maxDuration"), is(100));
        assertThat(config.getProperty("client.spider.pageLoadTime"), is(3));
        assertThat(config.getProperty("client.spider.shutdownTime"), is(10));
        assertThat(config.getProperty("client.spider.threads"), is(32));
        assertThat(config.getProperty("client.spider.logoutAvoidance"), is(false));
        assertThat(config.getProperty("client.spider.actionWaitTime"), is(2));

        assertThat(options.getBrowserId(), is("firefox-headless"));
        assertThat(options.getInitialLoadTimeInSecs(), is(4));
        assertThat(options.getMaxChildren(), is(100));
        assertThat(options.getMaxDepth(), is(10));
        assertThat(options.getMaxDuration(), is(100));
        assertThat(options.getPageLoadTimeInSecs(), is(3));
        assertThat(options.getShutdownTimeInSecs(), is(10));
        assertThat(options.getThreadCount(), is(32));
        assertThat(options.isLogoutAvoidance(), is(false));
        assertThat(options.getActionWaitTimeInSecs(), is(2));
    }
}
