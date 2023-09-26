/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link SeleniumOptions}. */
class SeleniumOptionsUnitTest extends TestUtils {

    private Path seleniumExtensionsDir;
    private SeleniumOptions options;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        seleniumExtensionsDir = Paths.get(Constant.getZapHome(), "selenium", "extensions");

        options = new SeleniumOptions();
    }

    @Test
    void shouldCreateSeleniumExtensionsDirOnLoad() {
        // Given / When
        options.load(new ZapXmlConfiguration());
        // Then
        assertThat(Files.isDirectory(seleniumExtensionsDir), is(equalTo(true)));
    }

    @Test
    void shouldNotFailToSetBrowserExtensionsIfExtensionsDirDoesNotExist() throws Exception {
        // Given
        options.load(new ZapXmlConfiguration());
        Files.deleteIfExists(seleniumExtensionsDir);
        // When / Then
        assertDoesNotThrow(() -> options.setBrowserExtensions(Collections.emptyList()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadConfigWithConfirmRemoveBrowserArgument(boolean value) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <confirmRemoveBrowserArg>\n"
                                + value
                                + "</confirmRemoveBrowserArg>\n"
                                + "</selenium>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveBrowserArgument(), is(equalTo(value)));
    }

    @Test
    void shouldLoadConfigWithInvalidConfirmRemoveBrowserArgument() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <confirmRemoveBrowserArg>not boolean</confirmRemoveBrowserArg>\n"
                                + "</selenium>");
        // When
        options.load(config);
        // Then
        assertThat(options.isConfirmRemoveBrowserArgument(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetAndPersistConfirmRemoveBrowserArgument(boolean value) throws Exception {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        // When
        options.setConfirmRemoveBrowserArgument(value);
        // Then
        assertThat(options.isConfirmRemoveBrowserArgument(), is(equalTo(value)));
        assertThat(config.getBoolean("selenium.confirmRemoveBrowserArg"), is(equalTo(value)));
    }

    static Stream<Arguments> browserNameKey() {
        return Stream.of(
                arguments("chrome", "selenium.chromeArgs.arg"),
                arguments("firefox", "selenium.firefoxArgs.arg"));
    }

    static Stream<String> invalidBrowserNames() {
        return Stream.of("not supported", null);
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldAddBrowserArgument(String browser, String key) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        BrowserArgument argument = new BrowserArgument("--arg", true);
        // When
        options.addBrowserArgument(browser, argument);
        // Then
        assertThat(options.getBrowserArguments(browser), hasSize(1));
        assertThat(config.getProperty(key + ".argument"), is(equalTo("--arg")));
        assertThat(config.getProperty(key + ".enabled"), is(equalTo(true)));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldThrowIfAddingNullBrowserArgument(String browser, String key) {
        // Given
        BrowserArgument argument = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> options.addBrowserArgument(browser, argument));
        assertThat(options.getBrowserArguments(browser), hasSize(0));
    }

    @ParameterizedTest
    @MethodSource("invalidBrowserNames")
    void shouldThrowIfAddingBrowserArgumentToInvalidBrowser(String browser) {
        // Given
        BrowserArgument argument = new BrowserArgument("--arg", true);
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.addBrowserArgument(browser, argument));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldSetBrowserArgumentEnabled(String browser, String key) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addBrowserArgument(browser, new BrowserArgument("--arg", true));
        options.addBrowserArgument(browser, new BrowserArgument("--other-arg", true));
        // When
        boolean removed = options.setBrowserArgumentEnabled(browser, "  --arg \t", false);
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getBrowserArguments(browser), hasSize(2));
        assertThat(config.getProperty(key + "(0).argument"), is(equalTo("--arg")));
        assertThat(config.getProperty(key + "(0).enabled"), is(equalTo(false)));
        assertThat(config.getProperty(key + "(1).argument"), is(equalTo("--other-arg")));
        assertThat(config.getProperty(key + "(1).enabled"), is(equalTo(true)));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldReturnFalseIfBrowserArgumentNotChanged(String browser, String key) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addBrowserArgument(browser, new BrowserArgument("--arg", true));
        options.addBrowserArgument(browser, new BrowserArgument("--other-arg", true));
        // When
        boolean removed = options.setBrowserArgumentEnabled(browser, "--not-same-other-arg", false);
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getBrowserArguments(browser), hasSize(2));
        assertThat(config.getProperty(key + "(0).argument"), is(equalTo("--arg")));
        assertThat(config.getProperty(key + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(key + "(1).argument"), is(equalTo("--other-arg")));
        assertThat(config.getProperty(key + "(1).enabled"), is(equalTo(true)));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldThrowIfSettingNullArgumentEnabled(String browser, String key) {
        // Given
        String argument = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> options.setBrowserArgumentEnabled(browser, argument, true));
        assertThat(options.getBrowserArguments(browser), hasSize(0));
    }

    @ParameterizedTest
    @MethodSource("invalidBrowserNames")
    void shouldThrowIfSettingArgumentEnabledToInvalidBrowser(String browser) {
        // Given
        String argument = "--arg";
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.setBrowserArgumentEnabled(browser, argument, true));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldRemoveBrowserArgument(String browser, String key) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addBrowserArgument(browser, new BrowserArgument("--arg", true));
        options.addBrowserArgument(browser, new BrowserArgument("--other-arg", true));
        // When
        boolean removed = options.removeBrowserArgument(browser, "   --arg \t");
        // Then
        assertThat(removed, is(equalTo(true)));
        assertThat(options.getBrowserArguments(browser), hasSize(1));
        assertThat(config.getProperty(key + "(0).argument"), is(equalTo("--other-arg")));
        assertThat(config.getProperty(key + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(key + "(1).argument"), is(nullValue()));
        assertThat(config.getProperty(key + "(1).enabled"), is(nullValue()));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldReturnFalseIfBrowserArgumentNotRemoved(String browser, String key) {
        // Given
        ZapXmlConfiguration config = new ZapXmlConfiguration();
        options.load(config);
        options.addBrowserArgument(browser, new BrowserArgument("--arg", true));
        options.addBrowserArgument(browser, new BrowserArgument("--other-arg", true));
        // When
        boolean removed = options.removeBrowserArgument(browser, "--not-same-other-arg");
        // Then
        assertThat(removed, is(equalTo(false)));
        assertThat(options.getBrowserArguments(browser), hasSize(2));
        assertThat(config.getProperty(key + "(0).argument"), is(equalTo("--arg")));
        assertThat(config.getProperty(key + "(0).enabled"), is(equalTo(true)));
        assertThat(config.getProperty(key + "(1).argument"), is(equalTo("--other-arg")));
        assertThat(config.getProperty(key + "(1).enabled"), is(equalTo(true)));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldThrowIfRemovingNullArgument(String browser, String key) {
        // Given
        String argument = null;
        // When / Then
        assertThrows(
                NullPointerException.class, () -> options.removeBrowserArgument(browser, argument));
        assertThat(options.getBrowserArguments(browser), hasSize(0));
    }

    @ParameterizedTest
    @MethodSource("invalidBrowserNames")
    void shouldThrowIfRemovingBrowserArgumentFromInvalidBrowser(String browser) {
        // Given
        String argument = "--arg";
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.removeBrowserArgument(browser, argument));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldLoadConfigWithBrowserArguments(String browser, String key) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <"
                                + browser
                                + "Args>\n"
                                + "      <arg>\n"
                                + "        <argument>--arg</argument>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </arg>\n"
                                + "      <arg>\n"
                                + "        <argument>--other-arg</argument>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </arg>\n"
                                + "  </"
                                + browser
                                + "Args>\n"
                                + "</selenium>");
        // When
        options.load(config);
        // Then
        assertThat(options.getBrowserArguments(browser), hasSize(2));
        assertThat(options.getBrowserArguments(browser).get(0).getArgument(), is(equalTo("--arg")));
        assertThat(options.getBrowserArguments(browser).get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getBrowserArguments(browser).get(1).getArgument(),
                is(equalTo("--other-arg")));
        assertThat(options.getBrowserArguments(browser).get(1).isEnabled(), is(equalTo(false)));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldSetAndPersistBrowserArguments(String browser, String key) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <"
                                + browser
                                + "Args>\n"
                                + "      <arg>\n"
                                + "        <argument>--arg</argument>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </arg>\n"
                                + "      <arg>\n"
                                + "        <argument>--other-arg</argument>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </arg>\n"
                                + "  </"
                                + browser
                                + "Args>\n"
                                + "</selenium>");
        options.load(config);
        List<BrowserArgument> arguments = options.getBrowserArguments(browser);
        options.load(new ZapXmlConfiguration());
        // When
        options.setBrowserArguments(browser, arguments);
        // Then
        assertThat(options.getBrowserArguments(browser), hasSize(2));
        assertThat(options.getBrowserArguments(browser).get(0).getArgument(), is(equalTo("--arg")));
        assertThat(options.getBrowserArguments(browser).get(0).isEnabled(), is(equalTo(true)));
        assertThat(
                options.getBrowserArguments(browser).get(1).getArgument(),
                is(equalTo("--other-arg")));
        assertThat(options.getBrowserArguments(browser).get(1).isEnabled(), is(equalTo(false)));
    }

    @ParameterizedTest
    @MethodSource("invalidBrowserNames")
    void shouldThrowIfSettingBrowserArgumentsToInvalidBrowser(String browser) {
        // Given
        List<BrowserArgument> arguments = List.of();
        // When / Then
        assertThrows(
                IllegalArgumentException.class,
                () -> options.setBrowserArguments(browser, arguments));
    }

    @ParameterizedTest
    @MethodSource("browserNameKey")
    void shouldLoadConfigWhileIgnoringInvalidBrowserArguments(String browser, String key) {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <"
                                + browser
                                + "Args>\n"
                                + "      <arg>\n"
                                + "        <argument></argument>\n"
                                + "        <enabled>true</enabled>\n"
                                + "      </arg>\n"
                                + "      <arg>\n"
                                + "        <enabled>false</enabled>\n"
                                + "      </arg>\n"
                                + "      <arg>\n"
                                + "        <argument>--other-arg</argument>\n"
                                + "        <enabled>not a boolean</enabled>\n"
                                + "      </arg>\n"
                                + "      <arg>\n"
                                + "        <argument>--valid-other-arg</argument>\n"
                                + "      </arg>\n"
                                + "  </"
                                + browser
                                + "Args>\n"
                                + "</selenium>");
        // When
        options.load(config);
        // Then
        assertThat(options.getBrowserArguments(browser), hasSize(1));
        assertThat(
                options.getBrowserArguments(browser).get(0).getArgument(),
                is(equalTo("--valid-other-arg")));
        assertThat(options.getBrowserArguments(browser).get(0).isEnabled(), is(equalTo(true)));
    }

    @ParameterizedTest
    @MethodSource("invalidBrowserNames")
    void shouldThrowIfGettingBrowserArgumentsFromInvalidBrowser(String browser) {
        assertThrows(IllegalArgumentException.class, () -> options.getBrowserArguments(browser));
    }

    @Test
    void shouldSetAndPersistFirefoxProfile() {
        // Given
        ZapXmlConfiguration config =
                configWith(
                        "<selenium>\n"
                                + "  <firefoxProfile>test-profile</firefoxProfile>\n"
                                + "</selenium>");
        options.load(config);
        String fxProfile = options.getFirefoxDefaultProfile();
        options.load(new ZapXmlConfiguration());
        // When
        options.setFirefoxDefaultProfile("profile2");
        // Then
        assertThat(fxProfile, is(equalTo("test-profile")));
        assertThat(options.getFirefoxDefaultProfile(), is(equalTo("profile2")));
    }

    @Test
    void shouldThrowIfSettingNullFirefoxProfile() {
        // Given / When / Then
        assertThrows(NullPointerException.class, () -> options.setFirefoxDefaultProfile(null));
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
