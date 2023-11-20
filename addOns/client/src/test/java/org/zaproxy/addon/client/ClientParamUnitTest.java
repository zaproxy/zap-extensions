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
    void shouldSetPscanningDisabled() {
        // Given
        clientParam.load(config);
        // When
        clientParam.setPscanEnabled(false);
        // Then
        assertThat(config.getProperty("client.pscanEnabled"), is(false));
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
