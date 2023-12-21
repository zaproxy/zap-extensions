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
package org.zaproxy.addon.client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.ArrayList;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link ClientOptions}. */
class ClientParamUnitTest {

    private ClientOptions clientParam;
    private ZapXmlConfiguration config;

    @BeforeEach
    void setUp() {
        clientParam = new ClientOptions();
        config = new ZapXmlConfiguration();
    }

    @Test
    void shouldUseTheRightDefaults() {
        // Given / When
        clientParam.load(config);
        // Then
        assertThat(clientParam.isPscanEnabled(), is(true));
        assertThat(clientParam.getPscanRulesDisabled().size(), is(0));
    }

    @Test
    void shouldUseTheRightValues() {
        // Given
        config.addProperty("client.pscanEnabled", false);
        config.addProperty("client.pscanRulesDisabled", Arrays.asList("1", "3"));
        // When
        clientParam.load(config);
        // Then
        assertThat(clientParam.isPscanEnabled(), is(false));
        assertThat(clientParam.getPscanRulesDisabled().size(), is(2));
        assertThat(clientParam.getPscanRulesDisabled().get(0), is(1));
        assertThat(clientParam.getPscanRulesDisabled().get(1), is(3));

        assertThat(clientParam.getBrowserId(), is("firefox-headless"));
        assertThat(clientParam.getInitialLoadTimeInSecs(), is(5));
        assertThat(clientParam.getMaxChildren(), is(0));
        assertThat(clientParam.getMaxDepth(), is(5));
        assertThat(clientParam.getMaxDuration(), is(0));
        assertThat(clientParam.getPageLoadTimeInSecs(), is(1));
        assertThat(clientParam.getShutdownTimeInSecs(), is(5));
        assertThat(clientParam.getThreadCount(), is(Constants.getDefaultThreadCount()));
    }

    @Test
    void shouldHandleBadValues() {
        // Given
        config.addProperty("client.pscanEnabled", "test");
        config.addProperty("client.pscanRulesDisabled", "test");
        // When
        clientParam.load(config);
        // Then
        assertThat(clientParam.isPscanEnabled(), is(true));
        assertThat(clientParam.getPscanRulesDisabled().size(), is(0));
    }

    @Test
    void shouldSetOptions() {
        // Given
        clientParam.load(config);
        // When
        clientParam.setPscanEnabled(false);
        clientParam.setBrowserId("test-browser");
        clientParam.setInitialLoadTimeInSecs(4);
        clientParam.setMaxChildren(100);
        clientParam.setMaxDepth(10);
        clientParam.setMaxDuration(100);
        clientParam.setPageLoadTimeInSecs(3);
        clientParam.setShutdownTimeInSecs(10);
        clientParam.setThreadCount(32);
        // Then
        assertThat(config.getProperty("client.pscanEnabled"), is(false));
        assertThat(config.getProperty("client.browserId"), is("test-browser"));
        assertThat(config.getProperty("client.initialLoadTime"), is(4));
        assertThat(config.getProperty("client.maxChildren"), is(100));
        assertThat(config.getProperty("client.maxDepth"), is(10));
        assertThat(config.getProperty("client.maxDuration"), is(100));
        assertThat(config.getProperty("client.pageLoadTime"), is(3));
        assertThat(config.getProperty("client.shutdownTime"), is(10));
        assertThat(config.getProperty("client.threads"), is(32));

        assertThat(clientParam.getPscanRulesDisabled().size(), is(0));
        assertThat(clientParam.getBrowserId(), is("test-browser"));
        assertThat(clientParam.getInitialLoadTimeInSecs(), is(4));
        assertThat(clientParam.getMaxChildren(), is(100));
        assertThat(clientParam.getMaxDepth(), is(10));
        assertThat(clientParam.getMaxDuration(), is(100));
        assertThat(clientParam.getPageLoadTimeInSecs(), is(3));
        assertThat(clientParam.getShutdownTimeInSecs(), is(10));
        assertThat(clientParam.getThreadCount(), is(32));
    }

    @Test
    void shouldSetPscanRulesDisabled() {
        // Given
        clientParam.load(config);
        // When
        clientParam.setPscanRulesDisabled(
                Arrays.asList(Integer.valueOf(2), Integer.valueOf(4), Integer.valueOf(8)));
        ArrayList<?> prop = (ArrayList<?>) config.getProperty("client.pscanRulesDisabled");
        // Then
        assertThat(prop.size(), is(3));
        assertThat(prop.get(0), is(2));
        assertThat(prop.get(1), is(4));
        assertThat(prop.get(2), is(8));
    }
}
