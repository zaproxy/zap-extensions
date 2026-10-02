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
package org.zaproxy.zap.extension.wappalyzer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer.Mode;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link TechDetectParam}. */
class TechDetectParamUnitTest {

    private TechDetectParam param;
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
        param = new TechDetectParam();
        configuration = new ZapXmlConfiguration();
    }

    @Test
    void shouldHaveConfigVersionKey() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.getConfigVersionKey(), is(equalTo("techdetect[@version]")));
    }

    @Test
    void shouldUseDefaultsWithFreshConfig() {
        // Given / When
        param.load(configuration);
        // Then
        assertThat(param.isEnabled(), is(equalTo(true)));
        assertThat(param.getMode(), is(equalTo(Mode.QUICK)));
        assertThat(param.isRaiseAlerts(), is(equalTo(true)));
    }

    @Test
    void shouldMigrateOldConfigKeysToNewOnes() {
        // Given
        configuration.setProperty("wappalyzer.enabled", false);
        configuration.setProperty("wappalyzer.mode", Mode.EXHAUSTIVE.name());
        configuration.setProperty("wappalyzer.alerts", false);
        // When
        param.load(configuration);
        // Then
        assertThat(param.isEnabled(), is(equalTo(false)));
        assertThat(param.getMode(), is(equalTo(Mode.EXHAUSTIVE)));
        assertThat(param.isRaiseAlerts(), is(equalTo(false)));
        assertThat(configuration.getProperty("wappalyzer.enabled"), is(nullValue()));
        assertThat(configuration.getProperty("wappalyzer.mode"), is(nullValue()));
        assertThat(configuration.getProperty("wappalyzer.alerts"), is(nullValue()));
        assertThat(configuration.getProperty("techdetect.enabled"), is(equalTo(false)));
        assertThat(
                configuration.getProperty("techdetect.mode"), is(equalTo(Mode.EXHAUSTIVE.name())));
        assertThat(configuration.getProperty("techdetect.alerts"), is(equalTo(false)));
    }

    @Test
    void shouldNotMigrateWhenOnlyNewConfigKeysPresent() {
        // Given
        configuration.setProperty("techdetect.enabled", false);
        configuration.setProperty("techdetect.mode", Mode.EXHAUSTIVE.name());
        configuration.setProperty("techdetect.alerts", false);
        // When
        param.load(configuration);
        // Then
        assertThat(param.isEnabled(), is(equalTo(false)));
        assertThat(param.getMode(), is(equalTo(Mode.EXHAUSTIVE)));
        assertThat(param.isRaiseAlerts(), is(equalTo(false)));
    }
}
