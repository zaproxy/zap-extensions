/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link PortScanParam}. */
class PortScanParamUnitTest {

    private PortScanParam param;
    private ZapXmlConfiguration configuration;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
        Control.initSingletonForTesting(mock(Model.class), mock(ExtensionLoader.class));
    }

    @AfterAll
    static void afterAll() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() {
        param = new PortScanParam();
        configuration = new ZapXmlConfiguration();
        param.load(configuration);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(param.getConfigVersionKey(), is(equalTo("portscan[@version]")));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 3, 12})
    void shouldLoadThreadsFromConfig(int threads) {
        // Given
        configuration.setProperty("portscan.threadPerHost", threads);
        // When
        param.load(configuration);
        // Then
        assertThat(param.getThreadPerScan(), is(equalTo(threads)));
    }

    @Test
    void shouldDefaultThreads() {
        try (MockedStatic<Constants> constants = mockStatic(Constants.class)) {
            // Given
            constants.when(Constants::getDefaultThreadCount).thenReturn(10);
            configuration = new ZapXmlConfiguration();
            // When
            param.load(configuration);
            // Then
            assertThat(param.getThreadPerScan(), is(equalTo(10)));
        }
    }

    @Test
    void shouldUpdateDefaultThreads() {
        try (MockedStatic<Constants> constants = mockStatic(Constants.class)) {
            // Given
            constants.when(Constants::getDefaultThreadCount).thenReturn(8);
            configuration = new ZapXmlConfiguration();
            configuration.setProperty("portscan.threadPerHost", 5);
            // When
            param.load(configuration);
            // Then
            assertThat(param.getThreadPerScan(), is(equalTo(8)));
        }
    }

    @Test
    void shouldNotUpdateNonDefaultThreads() {
        try (MockedStatic<Constants> constants = mockStatic(Constants.class)) {
            // Given
            constants.when(Constants::getDefaultThreadCount).thenReturn(8);
            configuration = new ZapXmlConfiguration();
            configuration.setProperty("portscan.threadPerHost", 3);
            // When
            param.load(configuration);
            // Then
            assertThat(param.getThreadPerScan(), is(equalTo(3)));
        }
    }
}
