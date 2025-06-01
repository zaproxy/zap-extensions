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
package org.zaproxy.addon.requester;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link RequesterParam}. */
class RequesterParamUnitTest {

    private static final String AUTO_FOCUS_KEY = "requester.autoFocus";

    private static final boolean DEFAULT_AUTO_FOCUS = true;

    private ZapXmlConfiguration config;
    private RequesterParam options;

    @BeforeEach
    void setUp() {
        options = new RequesterParam();
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(options.getConfigVersionKey(), is(equalTo("requester[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        // Given
        options = new RequesterParam();
        // When / Then
        assertDefaultValues();
    }

    private void assertDefaultValues() {
        assertThat(options.isAutoFocus(), is(equalTo(DEFAULT_AUTO_FOCUS)));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertDefaultValues();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithAutoFocus(boolean value) {
        // Given
        config.setProperty(AUTO_FOCUS_KEY, value);
        // When
        options.load(config);
        // Then
        assertThat(options.isAutoFocus(), is(equalTo(value)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"not boolean", ""})
    void shouldUseDefaultWithInvalidAutoFocus(String value) {
        // Given
        config.setProperty(AUTO_FOCUS_KEY, value);
        // When
        options.load(config);
        // Then
        assertThat(options.isAutoFocus(), is(equalTo(DEFAULT_AUTO_FOCUS)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistAutoFocus(boolean value) throws Exception {
        // Given / When
        options.setAutoFocus(value);
        // Then
        assertThat(options.isAutoFocus(), is(equalTo(value)));
        assertThat(config.getBoolean(AUTO_FOCUS_KEY), is(equalTo(value)));
    }
}
