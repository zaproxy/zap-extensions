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
package org.zaproxy.zap.extension.selenium.internal.stealth;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.openqa.selenium.ScriptKey;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chromium.ChromiumDriver;
import org.openqa.selenium.devtools.DevTools;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.selenium.SeleniumScriptUtils;

public class StealthManagerUnitTest {

    private static final String UA_CHROME_HEADLESS =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/60.3112.50 Safari/537.36";
    private static final String UA_CHROME_HEADFUL =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.3112.50 Safari/537.36";
    private static final String UA_CHROME_HEADFUL_MAC =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36";
    private static final String UA_FIREFOX_HEADFUL =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0";
    private static final String UA_ANDROID =
            "Mozilla/5.0 (Linux; U; Android 2.2; en-gb; Nexus One Build/FRF50) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1";

    StealthManager stealthManager;
    FirefoxDriver firefoxDriver;
    ChromiumDriver chromiumDriver;
    DevTools devTools;

    @BeforeEach
    void setUp() {
        stealthManager = new StealthManager();
        firefoxDriver = mock(FirefoxDriver.class);

        devTools = mock(DevTools.class);
        chromiumDriver = mock(ChromiumDriver.class);
        when(chromiumDriver.getDevTools()).thenReturn(devTools);
    }

    private SeleniumScriptUtils createUtils(WebDriver wd, String browserId) {
        return new SeleniumScriptUtils(
                wd, HttpSender.PROXY_INITIATOR, browserId, "127.0.0.1", 8080);
    }

    static Stream<Arguments> chromeProvider() {
        return Stream.of(
                arguments("chrome", UA_CHROME_HEADFUL),
                arguments("chrome-headless", UA_CHROME_HEADLESS));
    }

    static Stream<Arguments> firefoxProvider() {
        return Stream.of(
                arguments("firefox", UA_FIREFOX_HEADFUL),
                arguments("firefox-headless", UA_FIREFOX_HEADFUL));
    }

    @Test
    void evasionsAreLoaded() throws IOException {
        // Given the extension
        // When the extension is initialized
        stealthManager.loadEvasions();
        // Then utility code is loaded
        assertThat(stealthManager.getUtilCode(), not(emptyOrNullString()));
        // Then the evasions are loaded
        List<Evasion> evasions = stealthManager.getEvasions();
        assertThat(evasions.size(), equalTo(14));
        for (Evasion evasion : stealthManager.getEvasions()) {
            assertThat(evasion.getCode(), not(emptyOrNullString()));
        }
    }

    @Test
    void evasionsAreLoadedOnce() throws IOException {
        // Given evasions are loaded
        stealthManager.loadEvasions();
        int firstCallSize = stealthManager.getEvasions().size();
        // When evasions are loaded again
        stealthManager.loadEvasions();
        // Then evasions are not added to the list
        assertThat(firstCallSize, equalTo(stealthManager.getEvasions().size()));
    }

    /**
     * We're checking if there are obvious mistakes when refactoring the javascript code from
     * puppeteer.
     */
    @Test
    void badEvasionRefactor() throws IOException {
        // Given the extension is initialized
        stealthManager.loadEvasions();
        // When the code is loaded
        for (Evasion evasion : stealthManager.getEvasions()) {
            String code = evasion.getCode();
            // Then it does not have options from the puppeteer stealth plugin
            assertThat(code, not(containsString("opts.")));
            // Then it does not have NodeJS module references
            assertThat(code, not(containsString("module.")));
        }
    }

    @Test
    void buildUserAgentOverride_ChromeHeadless() {
        // Given chrome headless user agent
        String userAgent = UA_CHROME_HEADLESS;
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then headless mode is not identified
        assertThat(userAgentOverrides.get("userAgent").toString(), not(containsString("Headless")));
        // Then Linux is not identified
        assertThat(userAgentOverrides.get("userAgent").toString(), not(containsString("Linux")));
        assertThat(userAgentOverrides.get("platform").toString(), equalTo("Win64"));
        // Then Accept-Language is overridden
        assertThat(userAgentOverrides.get("acceptLanguage").toString(), not(emptyOrNullString()));
        // Then all user agent metadata is provided
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_WINDOWS));
        assertThat(metadata.get("platformVersion"), equalTo("10.0"));
        assertThat(metadata.get("architecture"), equalTo(StealthManager.ARCH_X86_64));
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
        assertThat(metadata.get("brands"), notNullValue());
        assertThat(metadata.get("fullVersion"), equalTo("60.3112.50"));
    }

    @Test
    void buildUserAgentOverride_ChromeHeadful_Linux() {
        // Given chrome headful user agent
        String userAgent = UA_CHROME_HEADFUL;
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then Linux is not identified
        assertThat(userAgentOverrides.get("userAgent").toString(), not(containsString("Linux")));
        assertThat(userAgentOverrides.get("platform").toString(), equalTo("Win64"));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then all user agent metadata is provided
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_WINDOWS));
        assertThat(metadata.get("platformVersion"), equalTo("10.0"));
        assertThat(metadata.get("architecture"), equalTo(StealthManager.ARCH_X86_64));
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
        assertThat(metadata.get("brands"), notNullValue());
        assertThat(metadata.get("fullVersion"), equalTo("60.3112.50"));
    }

    @Test
    void buildUserAgentOverride_ChromeHeadful_macOS() {
        // Given chrome headful user agent
        String userAgent = UA_CHROME_HEADFUL_MAC;
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then Linux is not identified
        assertThat(userAgentOverrides.get("userAgent").toString(), not(containsString("Linux")));
        assertThat(userAgentOverrides.get("userAgent").toString(), containsString("Macintosh"));
        assertThat(userAgentOverrides.get("platform").toString(), equalTo("MacIntel"));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then all user agent metadata is provided
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_MAC_OS_X));
        assertThat(metadata.get("platformVersion"), equalTo("10_15_7"));
        assertThat(metadata.get("architecture"), equalTo(StealthManager.ARCH_X86_64));
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
        assertThat(metadata.get("brands"), notNullValue());
        assertThat(metadata.get("fullVersion"), equalTo("117.0.0.0"));
    }

    @Test
    void buildUserAgentOverride_Chrome_MissingVersion() {
        // Given chrome headful user agent without version
        String userAgent =
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/NOVER Safari/537.36";
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then Linux is not identified
        assertThat(userAgentOverrides.get("userAgent").toString(), not(containsString("Linux")));
        assertThat(userAgentOverrides.get("platform").toString(), equalTo("Win64"));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then metadata object is provided
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        // Then metadata that depends on version is not provided
        assertThat(metadata.get("brands"), nullValue());
        assertThat(metadata.get("fullVersion"), nullValue());
        // Then all other user agent metadata
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_WINDOWS));
        assertThat(metadata.get("platformVersion"), equalTo("10.0"));
        assertThat(metadata.get("architecture"), equalTo(StealthManager.ARCH_X86_64));
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
    }

    @Test
    void buildUserAgentOverride_FirefoxHeadful() {
        // Given firefox headful user agent
        String userAgent =
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/118.0";
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then user agent override is provided
        assertThat(userAgentOverrides.get("userAgent").toString(), not(emptyOrNullString()));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then non-chrome specific user agent metadata is provided
        assertThat(userAgentOverrides.get("platform").toString(), equalTo("MacIntel"));
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_MAC_OS_X));
        assertThat(metadata.get("platformVersion"), equalTo("10.15"));
        assertThat(metadata.get("architecture"), notNullValue());
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
        assertThat(metadata.get("brands"), nullValue());
        assertThat(metadata.get("fullVersion"), nullValue());
    }

    @Test
    void buildUserAgentOverride_Android() {
        // Given firefox headful user agent
        String userAgent = UA_ANDROID;
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then user agent override is provided
        assertThat(userAgentOverrides.get("userAgent").toString(), not(emptyOrNullString()));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then non-chrome specific user agent metadata is provided
        assertThat(
                userAgentOverrides.get("platform").toString(),
                equalTo(StealthManager.PLATFORM_ANDROID));
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), equalTo(StealthManager.PLATFORM_ANDROID));
        assertThat(metadata.get("platformVersion"), equalTo("2.2"));
        assertThat(metadata.get("architecture"), equalTo(""));
        assertThat(metadata.get("model"), equalTo("Nexus One Build/FRF50"));
        assertThat(metadata.get("mobile"), equalTo(true));
        assertThat(metadata.get("brands"), nullValue());
        assertThat(metadata.get("fullVersion"), nullValue());
    }

    @Test
    void buildUserAgentOverride_Simple() {
        // Given simple user agent
        String userAgent = "Mozilla/5.0";
        // When user agent overrides are built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then user agent override is provided
        assertThat(userAgentOverrides.get("userAgent").toString(), not(emptyOrNullString()));
        // Then Accept-Language is not overridden
        assertThat(userAgentOverrides.get("acceptLanguage"), nullValue());
        // Then non-chrome specific user agent metadata is provided
        assertThat(userAgentOverrides.get("platform").toString(), not(emptyOrNullString()));
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata =
                (Map<String, Object>) userAgentOverrides.get("userAgentMetadata");
        assertThat(metadata, notNullValue());
        assertThat(metadata.get("platform"), notNullValue());
        assertThat(metadata.get("platformVersion"), notNullValue());
        assertThat(metadata.get("architecture"), notNullValue());
        assertThat(metadata.get("model"), notNullValue());
        assertThat(metadata.get("mobile"), equalTo(false));
        assertThat(metadata.get("brands"), nullValue());
        assertThat(metadata.get("fullVersion"), nullValue());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void buildUserAgentOverride_NullOrEmpty(String userAgent) {
        // Given an user agent
        // When the stealth user agent is built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then no error occurs
        assertThat(userAgentOverrides, nullValue());
    }

    @ParameterizedTest
    @ValueSource(strings = {"UserAgent", "This is a invalid user agent;"})
    void buildUserAgentOverride_Invalid(String userAgent) {
        // Given an invalid user agent
        // When the stealth user agent is built
        Map<String, Object> userAgentOverrides = stealthManager.buildUserAgentOverrides(userAgent);
        // Then the original user agent is returned
        assertThat(userAgentOverrides.get("userAgent"), equalTo(userAgent));
    }

    @ParameterizedTest()
    @ValueSource(strings = {"firefox", "firefox-headless"})
    void firefoxNotSupported(String browserId) {
        // Given firefox web driver
        SeleniumScriptUtils utils = createUtils(firefoxDriver, browserId);
        // When stealth attempted
        stealthManager.browserLaunched(utils);
        // Then no scripts are executed
        verify(firefoxDriver, never()).executeScript(any(String.class), any());
        verify(firefoxDriver, never()).executeScript(any(ScriptKey.class), any());
    }

    @ParameterizedTest()
    @MethodSource("chromeProvider")
    void chromeSupported(String browserId, String userAgent) {
        // Given chrome web driver
        SeleniumScriptUtils utils = createUtils(chromiumDriver, browserId);
        when(chromiumDriver.executeScript("return navigator.userAgent")).thenReturn(userAgent);
        // When stealth attempted
        stealthManager.browserLaunched(utils);
        // Then dev tools session is created
        verify(devTools, times(1)).createSession();
        // Then user agent is overridden
        verify(chromiumDriver, times(1)).executeScript("return navigator.userAgent");
        verify(chromiumDriver, times(1))
                .executeCdpCommand(eq("Network.setUserAgentOverride"), any());
        // Then 15 scripts are added
        verify(chromiumDriver, times(1))
                .executeCdpCommand(eq("Page.addScriptToEvaluateOnNewDocument"), any());
    }

    @Test
    void addScriptToEvaluateOnNewDocument() {
        // Given JavaScript code
        String code = "return;";
        // When requested to evaluate on new document
        stealthManager.addScriptToEvaluateOnNewDocument(chromiumDriver, code);
        // Then code is registered with CDP
        verify(chromiumDriver, times(1))
                .executeCdpCommand(
                        "Page.addScriptToEvaluateOnNewDocument",
                        Collections.singletonMap("source", code));
    }

    @ParameterizedTest()
    @MethodSource("chromeProvider")
    void filterEvasionsByBrowser_Chrome(String browserId, String userAgent) throws IOException {
        // Given chrome
        // When filtering evasions by browser
        List<Evasion> evasions = stealthManager.filterEvasionsByBrowser(browserId);
        // Then 14 evasions are available
        assertThat(evasions.size(), equalTo(14));
    }

    @ParameterizedTest()
    @MethodSource("firefoxProvider")
    void filterEvasionsByBrowser_Firefox(String browserId, String userAgent) throws IOException {
        // Given firefox
        // When filtering evasions by browser
        List<Evasion> evasions = stealthManager.filterEvasionsByBrowser(browserId);
        // Then 14 evasions are available
        assertThat(evasions.size(), equalTo(8));
    }

    @Test
    void testGetPlatform() {
        // Given
        // When Mac OS user agent is provided
        // Then Mac OS is returned
        assertThat(
                stealthManager.getPlatform(UA_FIREFOX_HEADFUL, true),
                equalTo(StealthManager.PLATFORM_MAC_OS_X));
        assertThat(stealthManager.getPlatform(UA_FIREFOX_HEADFUL, false), equalTo("MacIntel"));
        // When Linux user agent is provided
        // Then Linux platform is returned
        assertThat(
                stealthManager.getPlatform(UA_CHROME_HEADLESS, true),
                equalTo(StealthManager.PLATFORM_LINUX));
        assertThat(
                stealthManager.getPlatform(UA_CHROME_HEADLESS, false),
                equalTo(StealthManager.PLATFORM_LINUX));
        // When Windows user agent is provided
        // Then Windows platform is returned
        assertThat(
                stealthManager.getPlatform("(Windows NT 10.0; Win64; x64)", true),
                equalTo(StealthManager.PLATFORM_WINDOWS));
        assertThat(
                stealthManager.getPlatform("(Windows NT 10.0; Win64; x64)", false),
                equalTo("Win64"));
        // When unknown platform is provided
        // Then Windows platform is returned
        assertThat(
                stealthManager.getPlatform("(BeOS 4.1; BeOs; x86_64)", true),
                equalTo(StealthManager.PLATFORM_WINDOWS));
        assertThat(stealthManager.getPlatform("(BeOS 4.1; BeOs; x86_64)", false), equalTo("Win64"));
    }

    @Test
    void testGetPlatformVersion() {
        // Given
        // When Mac OS X platform
        // Then Mac OS X version is extracted
        assertThat(stealthManager.getPlatformVersion(UA_FIREFOX_HEADFUL), equalTo("10.15"));
        // When Android platform
        // Then Android version is extracted
        assertThat(stealthManager.getPlatformVersion(UA_ANDROID), equalTo("2.2"));
        // When Windows platform
        // Then Windows version is extracted
        assertThat(
                stealthManager.getPlatformVersion("(Windows NT 10.0; Windows; x64)"),
                equalTo("10.0"));
        // When Ubuntu platform
        // Then empty string
        assertThat(stealthManager.getPlatformVersion("(Ubuntu 22.04; Linux; x64)"), emptyString());
        // When no platform
        // Then empty string
        assertThat(stealthManager.getPlatformVersion(""), emptyString());
    }

    @Test
    void testIsMobile() {
        // Given
        // When Chrome user agent
        // Then is not mobile
        assertThat(stealthManager.isMobile(UA_CHROME_HEADFUL), equalTo(false));
        // When Firefox user agent
        // Then is not mobile
        assertThat(stealthManager.isMobile(UA_FIREFOX_HEADFUL), equalTo(false));
        // When Android user agent
        // Then is not mobile
        assertThat(stealthManager.isMobile(UA_ANDROID), equalTo(true));
        // When empty user agent
        // Then is not mobile
        assertThat(stealthManager.isMobile(""), equalTo(false));
    }

    @Test
    void testGetPlatformArch() {
        // Given
        // When Chrome user agent
        // Then x86
        assertThat(
                stealthManager.getPlatformArch(UA_CHROME_HEADFUL),
                equalTo(StealthManager.ARCH_X86_64));
        // When Firefox user agent
        // Then x86
        assertThat(
                stealthManager.getPlatformArch(UA_FIREFOX_HEADFUL),
                equalTo(StealthManager.ARCH_X86_64));
        // When Windows 64-bit platform
        // Then x64
        assertThat(
                stealthManager.getPlatformArch("(Windows NT 10.0; Windows; Win64)"),
                equalTo(StealthManager.ARCH_X86_64));
        // When Android user agent
        // Then empty string
        assertThat(stealthManager.getPlatformArch(UA_ANDROID), equalTo(""));
        // When empty user agent
        // Then x86
        assertThat(stealthManager.getPlatformArch(""), equalTo("x86"));
    }

    @Test
    void testGetPlatformModel() {
        // Given
        // When Chrome user agent
        // Then empty string
        assertThat(stealthManager.getPlatformModel(UA_CHROME_HEADFUL), equalTo(""));
        // When Firefox user agent
        // Then empty string
        assertThat(stealthManager.getPlatformModel(UA_FIREFOX_HEADFUL), equalTo(""));
        // When Android user agent
        // Then empty string
        assertThat(stealthManager.getPlatformModel(UA_ANDROID), equalTo("Nexus One Build/FRF50"));
        // When empty user agent
        // Then empty string
        assertThat(stealthManager.getPlatformModel(""), equalTo(""));
    }
}
