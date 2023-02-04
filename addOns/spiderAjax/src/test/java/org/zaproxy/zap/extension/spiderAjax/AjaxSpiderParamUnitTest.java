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
package org.zaproxy.zap.extension.spiderAjax;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link AjaxSpiderParam}. */
class AjaxSpiderParamUnitTest {

    private AjaxSpiderParam param;
    private ZapXmlConfiguration configuration;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
    }

    @AfterAll
    static void afterAll() {
        Constant.messages = null;
    }

    @BeforeEach
    void setUp() {
        param = new AjaxSpiderParam();
        configuration = new ZapXmlConfiguration();
        param.load(configuration);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(param.getConfigVersionKey(), is(equalTo("ajaxSpider[@version]")));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(ints = {1, 2, 3, 4})
    void shouldHaveAllowedResourcesByDefault(Integer version) {
        // Given
        configuration.setProperty(param.getConfigVersionKey(), version);
        // When
        param.load(configuration);
        // Then
        assertThat(
                param.getAllowedResources(),
                contains(
                        allowedResource("^http.*\\.js(?:\\?.*)?$"),
                        allowedResource("^http.*\\.css(?:\\?.*)?$")));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 3, 10})
    void shouldLoadThreadsFromConfig(int browsers) {
        // Given
        configuration.setProperty("ajaxSpider.numberOfBrowsers", browsers);
        // When
        param.load(configuration);
        // Then
        assertThat(param.getNumberOfBrowsers(), is(equalTo(browsers)));
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
            assertThat(param.getNumberOfBrowsers(), is(equalTo(10)));
        }
    }

    @Test
    void shouldUpdateDefaultThreads() {
        try (MockedStatic<Constants> constants = mockStatic(Constants.class)) {
            // Given
            constants.when(Constants::getDefaultThreadCount).thenReturn(10);
            configuration = new ZapXmlConfiguration();
            configuration.setProperty("ajaxSpider[@version]", 1);
            configuration.setProperty("ajaxSpider.numberOfBrowsers", 1);
            // When
            param.load(configuration);
            // Then
            assertThat(param.getNumberOfBrowsers(), is(equalTo(10)));
        }
    }

    @Test
    void shouldNotUpdateNonDefaultThreads() {
        try (MockedStatic<Constants> constants = mockStatic(Constants.class)) {
            // Given
            constants.when(Constants::getDefaultThreadCount).thenReturn(10);
            configuration = new ZapXmlConfiguration();
            configuration.setProperty("ajaxSpider[@version]", 1);
            configuration.setProperty("ajaxSpider.numberOfBrowsers", 3);
            // When
            param.load(configuration);
            // Then
            assertThat(param.getNumberOfBrowsers(), is(equalTo(3)));
        }
    }

    private static AllowedResource allowedResource(String regex) {
        return new AllowedResource(AllowedResource.createDefaultPattern(regex), true);
    }
}
