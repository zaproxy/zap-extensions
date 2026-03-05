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
package org.zaproxy.addon.mcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link McpParam}. */
class McpParamUnitTest {

    private ZapXmlConfiguration config;
    private McpParam param;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ROOT);
        param = new McpParam();
        config = new ZapXmlConfiguration();
        param.load(config);
    }

    @Test
    void shouldUseDefaultPortWhenNotInConfig() {
        assertThat(param.getPort(), is(equalTo(McpParam.DEFAULT_PORT)));
    }

    @Test
    void shouldLoadPortFromConfig() {
        config.setProperty("mcp.port", 9000);
        param.load(config);

        assertThat(param.getPort(), is(equalTo(9000)));
    }

    @Test
    void shouldSavePortToConfig() {
        param.setPort(12345);

        assertThat(config.getInt("mcp.port", -1), is(equalTo(12345)));
    }

    @Test
    void shouldUseDefaultSecurityKeyEnabledWhenNotInConfig() {
        assertThat(param.isSecurityKeyEnabled(), is(true));
    }

    @Test
    void shouldLoadSecurityKeyEnabledFromConfig() {
        config.setProperty("mcp.securityKeyEnabled", false);
        param.load(config);

        assertThat(param.isSecurityKeyEnabled(), is(false));
    }

    @Test
    void shouldReturnNullRequiredKeyWhenDisabled() {
        param.setSecurityKeyEnabled(false);
        param.setSecurityKey("some-key");

        assertThat(param.getRequiredSecurityKey(), is(nullValue()));
    }

    @Test
    void shouldReturnNullRequiredKeyWhenKeyIsBlank() {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("");

        assertThat(param.getRequiredSecurityKey(), is(nullValue()));
    }

    @Test
    void shouldReturnKeyWhenEnabledAndSet() {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("my-secret-key");

        assertThat(param.getRequiredSecurityKey(), is(equalTo("my-secret-key")));
    }

    @Test
    void shouldGenerateRandomKeyWithCorrectLength() {
        String key = McpParam.generateRandomKeyForUi();

        assertThat(key.length(), is(equalTo(32)));
        assertThat(key, matchesRegex("\\d{32}"));
    }

    @Test
    void shouldGenerateDifferentKeysEachTime() {
        String key1 = McpParam.generateRandomKeyForUi();
        String key2 = McpParam.generateRandomKeyForUi();

        assertThat(key1, is(not(equalTo(key2))));
    }

    @Test
    void shouldAcceptShortSecurityKey() {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("short");

        assertThat(param.getRequiredSecurityKey(), is(equalTo("short")));
    }

    @Test
    void shouldAcceptLongSecurityKey() {
        String longKey = "a".repeat(100);
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey(longKey);

        assertThat(param.getRequiredSecurityKey(), is(equalTo(longKey)));
    }

    @Test
    void shouldAcceptSecurityKeyWithSpecialCharacters() {
        param.setSecurityKeyEnabled(true);
        param.setSecurityKey("mixed-123_key");

        assertThat(param.getRequiredSecurityKey(), is(equalTo("mixed-123_key")));
    }

    @Test
    void shouldUseDefaultRecordInHistoryWhenNotInConfig() {
        assertThat(param.isRecordInHistory(), is(false));
    }

    @Test
    void shouldLoadRecordInHistoryFromConfig() {
        config.setProperty("mcp.recordInHistory", true);
        param.load(config);

        assertThat(param.isRecordInHistory(), is(true));
    }

    @Test
    void shouldSaveRecordInHistoryToConfig() {
        param.setRecordInHistory(true);

        assertThat(config.getBoolean("mcp.recordInHistory", false), is(true));
    }
}
