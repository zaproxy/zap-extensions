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
package org.zaproxy.addon.network;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.addon.network.internal.GlobalExclusion;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link GlobalExclusionsOptions}. */
class GlobalExclusionsOptionsUnitTest {

    private static final String CONFIRM_REMOVE_KEY =
            "network.globalExclusions.exclusions.confirmRemove";

    private static final String GLOBAL_EXCLUSION_KEY =
            "network.globalExclusions.exclusions.exclusion";

    private ZapXmlConfiguration config;
    private GlobalExclusionsOptions options;

    @BeforeEach
    void setUp() {
        options = new GlobalExclusionsOptions();
        config = new ZapXmlConfiguration();
        options.load(config);
    }

    @Test
    void shouldHaveConfigVersionKey() {
        assertThat(
                options.getConfigVersionKey(), is(equalTo("network.globalExclusions[@version]")));
    }

    @Test
    void shouldHaveDefaultValues() {
        // Given
        options = new GlobalExclusionsOptions();
        // When / Then
        assertDefaultValues();
        assertThat(options.getGlobalExclusions(), is(empty()));
    }

    private void assertDefaultValues() {
        assertThat(options.isConfirmRemoveGlobalExclusions(), is(equalTo(true)));
    }

    @Test
    void shouldLoadEmptyConfig() {
        // Given
        ZapXmlConfiguration emptyConfig = new ZapXmlConfiguration();
        // When
        options.load(emptyConfig);
        // Then
        assertDefaultValues();
        assertThat(options.getGlobalExclusions(), is(not(empty())));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveGlobalExclusions(boolean value) {
        // Given
        config.setProperty(CONFIRM_REMOVE_KEY, value);
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveGlobalExclusions(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveGlobalExclusions() {
        // Given
        config.setProperty(CONFIRM_REMOVE_KEY, "not boolean");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveGlobalExclusions(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistConfirmRemoveGlobalExclusions(boolean confirm) throws Exception {
        // Given / When
        options.setConfirmRemoveGlobalExclusions(confirm);
        // Then
        assertThat(options.isConfirmRemoveGlobalExclusions(), is(equalTo(confirm)));
        assertThat(config.getBoolean(CONFIRM_REMOVE_KEY), is(equalTo(confirm)));
    }

    @Test
    void shouldLoadConfigWithGlobalExclusions() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <globalExclusions version=\"1\">\n"
                                + "    <exclusions>\n"
                                + "      <exclusion>"
                                + "        <name>Name 1</name>\n"
                                + "        <value>Value 1</value>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </exclusion>"
                                + "      <exclusion>"
                                + "        <name>Name 2</name>\n"
                                + "        <value>Value 2</value>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </exclusion>"
                                + "    </exclusions>\n"
                                + "  </globalExclusions>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getGlobalExclusions(), hasSize(2));
        assertExclusion(0, "Name 1", "Value 1", true);
        assertExclusion(1, "Name 2", "Value 2", false);
    }

    @Test
    void shouldSetAndPersistGlobalExclusions() {
        // Given
        List<GlobalExclusion> exclusions =
                List.of(
                        exclusion("Name 1", "Value 1", true),
                        exclusion("Name 2", "Value 2", false));
        // When
        options.setGlobalExclusions(exclusions);
        // Then
        assertThat(options.getGlobalExclusions(), hasSize(2));
        assertPersistedExclusion(0, "Name 1", "Value 1", true);
        assertPersistedExclusion(1, "Name 2", "Value 2", false);
    }

    @Test
    void shouldLoadConfigWhileIgnoringInvalidGlobalExclusions() {
        // Given
        config =
                configWith(
                        "<network>\n"
                                + "  <globalExclusions version=\"1\">\n"
                                + "    <exclusions>\n"
                                + "      <exclusion>"
                                + "        <name>Name 1</name>\n"
                                + "        <value>*</value>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </exclusion>"
                                + "      <exclusion>"
                                + "        <name>Name 2</name>\n"
                                + "        <value></value>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </exclusion>"
                                + "      <exclusion>"
                                + "        <name>Name 3</name>\n"
                                + "        <value>Value 3</value>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </exclusion>"
                                + "    </exclusions>\n"
                                + "  </globalExclusions>\n"
                                + "</network>");
        // When
        options.load(config);
        // Then
        assertThat(options.getGlobalExclusions(), hasSize(1));
        assertExclusion(0, "Name 3", "Value 3", false);
    }

    @Test
    void shouldMigrateCoreOptions() {
        // Given
        config =
                configWith(
                        "<globalexcludeurl>\n"
                                + "  <confirmRemoveToken>false</confirmRemoveToken>\n"
                                + "  <url_list>\n"
                                + "    <url>\n"
                                + "      <description>Name</description>\n"
                                + "      <regex>Value</regex>\n"
                                + "      <enabled>false</enabled>\n"
                                + "    </url>\n"
                                + "  </url_list>\n"
                                + "</globalexcludeurl>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveGlobalExclusions(), is(equalTo(false)));
        assertExclusion(0, "Name", "Value", false);
    }

    private static GlobalExclusion exclusion(String name, String value, boolean enabled) {
        return new GlobalExclusion(name, value, enabled);
    }

    private void assertPersistedExclusion(int index, String name, String value, Boolean enabled) {
        String prefixKey = GLOBAL_EXCLUSION_KEY + "(" + index + ").";
        assertThat(config.getProperty(prefixKey + "name"), is(equalTo(name)));
        assertThat(config.getProperty(prefixKey + "value"), is(equalTo(value)));
        assertThat(config.getProperty(prefixKey + "enabled"), is(equalTo(enabled)));
    }

    private void assertExclusion(int index, String name, String value, boolean enabled) {
        GlobalExclusion exclusion = options.getGlobalExclusions().get(index);
        assertThat(exclusion.getName(), is(equalTo(name)));
        assertThat(exclusion.getValue(), is(equalTo(value)));
        assertThat(exclusion.isEnabled(), is(equalTo(enabled)));
    }

    private static ZapXmlConfiguration configWith(String value) {
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        String contents =
                "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
                        + "<config>\n"
                        + value
                        + "\n</config>";
        try {
            config.load(new ByteArrayInputStream(contents.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return config;
    }
}
