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
package org.zaproxy.zap.extension.selenium;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.quality.Strictness;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgument;
import org.zaproxy.zap.extension.selenium.internal.BrowserPreference;
import org.zaproxy.zap.extension.selenium.internal.CustomBrowserImpl;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit tests for {@link ExtensionSelenium}. */
class ExtensionSeleniumUnitTest extends TestUtils {

    private static final int REQUESTER = 100;
    private static final String PROXY_ADDRESS = "127.0.0.1";
    private static final int PROXY_PORT = 8080;

    private Model model;
    private SeleniumOptions seleniumOptions;

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionSelenium());
        setUpZap();
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);

        OptionsParam optionsParam = new OptionsParam();
        optionsParam.load(new ZapXmlConfiguration());
        given(model.getOptionsParam()).willReturn(optionsParam);

        seleniumOptions = new SeleniumOptions();
        optionsParam.addParamSet(seleniumOptions);
    }

    @Nested
    class BuildConfigFromBrowser {

        @Test
        void shouldIncludeOptionsArgumentsAndPreferencesForChrome() {
            seleniumOptions.addBrowserArgument(
                    Browser.CHROME.getId(), new BrowserArgument("--option-arg", true));
            seleniumOptions.addBrowserPreference(
                    Browser.CHROME.getId(),
                    new BrowserPreference("option.pref.name", "option.pref.value", true));

            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getRequester(), is(REQUESTER));
            assertThat(config.getProxyAddress(), is(PROXY_ADDRESS));
            assertThat(config.getProxyPort(), is(PROXY_PORT));
            assertThat(config.isHeadless(), is(true));
            assertThat(config.getType(), is(DriverConfiguration.DriverType.CHROMIUM));
            assertThat(config.getArguments(), contains("--option-arg"));
            assertThat(config.getPreferences(), hasEntry("option.pref.name", "option.pref.value"));
        }

        @Test
        void shouldAppendExtraArguments() {
            seleniumOptions.addBrowserArgument(
                    Browser.CHROME.getId(), new BrowserArgument("--from-options", true));

            List<String> extraArgs = List.of("--user-agent=ZAP-Test", "--extra-arg");
            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            null,
                            PROXY_PORT,
                            c -> {},
                            false,
                            extraArgs,
                            null);

            assertThat(
                    config.getArguments(),
                    containsInAnyOrder("--from-options", "--user-agent=ZAP-Test", "--extra-arg"));
        }

        @Test
        void shouldMergeExtraPreferences() {
            seleniumOptions.addBrowserPreference(
                    Browser.CHROME.getId(),
                    new BrowserPreference("options.pref", "from-options", true));

            Map<String, String> extraPrefs =
                    Map.of("extra.pref", "extra-value", "another.pref", "another-value");
            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            c -> {},
                            false,
                            null,
                            extraPrefs);

            assertThat(config.getPreferences(), hasEntry("options.pref", "from-options"));
            assertThat(config.getPreferences(), hasEntry("extra.pref", "extra-value"));
            assertThat(config.getPreferences(), hasEntry("another.pref", "another-value"));
        }

        @Test
        void shouldExcludeDisabledArgumentsAndPreferences() {
            seleniumOptions.addBrowserArgument(
                    Browser.CHROME.getId(), new BrowserArgument("--enabled-arg", true));
            seleniumOptions.addBrowserArgument(
                    Browser.CHROME.getId(), new BrowserArgument("--disabled-arg", false));
            seleniumOptions.addBrowserPreference(
                    Browser.CHROME.getId(), new BrowserPreference("enabled.pref", "v1", true));
            seleniumOptions.addBrowserPreference(
                    Browser.CHROME.getId(), new BrowserPreference("disabled.pref", "v2", false));

            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            null,
                            PROXY_PORT,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getArguments(), contains("--enabled-arg"));
            assertThat(config.getPreferences(), hasEntry("enabled.pref", "v1"));
            assertThat(config.getPreferences(), is(equalTo(Map.of("enabled.pref", "v1"))));
        }

        @Test
        void shouldHaveEmptyArgumentsForFirefoxHeadless() {
            // Firefox arguments are applied via addFirefoxArguments in createWebDriver, not in
            // config
            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.FIREFOX_HEADLESS,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getType(), is(DriverConfiguration.DriverType.FIREFOX));
            assertThat(config.isHeadless(), is(true));
            assertThat(config.getArguments(), is(equalTo(Collections.emptyList())));
        }

        @Test
        void shouldHandleNullExtraArgumentsAndPreferences() {
            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getArguments(), is(equalTo(Collections.emptyList())));
            assertThat(config.getPreferences(), is(equalTo(Collections.emptyMap())));
        }

        @Test
        void shouldHandleEmptyExtraArgumentsAndPreferences() {
            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromBrowser(
                            Browser.CHROME_HEADLESS,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            c -> {},
                            false,
                            Collections.emptyList(),
                            Collections.emptyMap());

            assertThat(config.getArguments(), is(equalTo(Collections.emptyList())));
            assertThat(config.getPreferences(), is(equalTo(Collections.emptyMap())));
        }
    }

    @Nested
    class BuildConfigFromCustomBrowser {

        @Test
        void shouldIncludeCustomArgumentsAndPreferences() {
            CustomBrowserImpl customBrowser =
                    new CustomBrowserImpl(
                            "TestCr",
                            "/driver",
                            "/binary",
                            CustomBrowserImpl.BrowserType.CHROMIUM,
                            List.of(
                                    new BrowserArgument("--custom-arg", true),
                                    new BrowserArgument("--disabled", false)),
                            List.of(
                                    new BrowserPreference("custom.pref", "customVal", true),
                                    new BrowserPreference("disabled.pref", "x", false)));

            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromCustomBrowser(
                            customBrowser,
                            REQUESTER,
                            PROXY_ADDRESS,
                            PROXY_PORT,
                            true,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getRequester(), is(REQUESTER));
            assertThat(config.getProxyAddress(), is(PROXY_ADDRESS));
            assertThat(config.getProxyPort(), is(PROXY_PORT));
            assertThat(config.isHeadless(), is(true));
            assertThat(config.getType(), is(DriverConfiguration.DriverType.CHROMIUM));
            assertThat(config.getArguments(), contains("--custom-arg"));
            assertThat(config.getPreferences(), hasEntry("custom.pref", "customVal"));
            assertThat(config.getPreferences().size(), is(1));
        }

        @Test
        void shouldAppendExtraArgumentsAndMergeExtraPreferences() {
            CustomBrowserImpl customBrowser =
                    new CustomBrowserImpl(
                            "TestCr",
                            null,
                            null,
                            CustomBrowserImpl.BrowserType.CHROMIUM,
                            List.of(new BrowserArgument("--from-browser", true)),
                            List.of(new BrowserPreference("browser.pref", "browserVal", true)));

            List<String> extraArgs = List.of("--extra-arg");
            Map<String, String> extraPrefs = Map.of("extra.pref", "extraVal");

            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromCustomBrowser(
                            customBrowser,
                            REQUESTER,
                            null,
                            PROXY_PORT,
                            false,
                            c -> {},
                            false,
                            extraArgs,
                            extraPrefs);

            assertThat(config.getArguments(), containsInAnyOrder("--from-browser", "--extra-arg"));
            assertThat(config.getPreferences(), hasEntry("browser.pref", "browserVal"));
            assertThat(config.getPreferences(), hasEntry("extra.pref", "extraVal"));
        }

        @Test
        void shouldHandleNullExtraArgumentsAndPreferences() {
            CustomBrowserImpl customBrowser =
                    new CustomBrowserImpl(
                            "TestFx",
                            null,
                            null,
                            CustomBrowserImpl.BrowserType.FIREFOX,
                            List.of(new BrowserArgument("--headless", true)),
                            List.of());

            DriverConfiguration config =
                    ExtensionSelenium.buildConfigFromCustomBrowser(
                            customBrowser,
                            REQUESTER,
                            null,
                            PROXY_PORT,
                            true,
                            c -> {},
                            false,
                            null,
                            null);

            assertThat(config.getArguments(), contains("--headless"));
            assertThat(config.getPreferences(), is(equalTo(Collections.emptyMap())));
        }
    }

    @Test
    void shouldReturnNonEmptyNameForEachBrowser() {
        for (Browser browser : Browser.values()) {
            String name = ExtensionSelenium.getName(browser);
            assertThat("Name for " + browser + " should be non-empty", name, is(not(equalTo(""))));
        }
    }

    @Test
    void shouldReturnFalseForSafari() {
        assertThat(ExtensionSelenium.isConfigured(Browser.SAFARI), is(false));
    }

    @ParameterizedTest
    @EnumSource(
            value = Browser.class,
            names = {"CHROME", "FIREFOX", "EDGE", "HTML_UNIT"})
    void shouldReturnTrueForConfiguredBrowsers(Browser browser) {
        assertThat(ExtensionSelenium.isConfigured(browser), is(true));
    }

    @Test
    void shouldContainHtmlUnitChromeAndFirefox() {
        ExtensionSelenium extension = new ExtensionSelenium();
        extension.init();

        List<Browser> browsers = extension.getConfiguredBrowsers();

        assertThat(browsers, hasItem(Browser.HTML_UNIT));
        assertThat(browsers, hasItem(Browser.CHROME));
        assertThat(browsers, hasItem(Browser.FIREFOX));
    }

    @Nested
    class GetWebDriver {

        private ExtensionSelenium extension;

        @BeforeEach
        void initExtension() {
            extension = new ExtensionSelenium();
            extension.init();
        }

        @Test
        void shouldThrowForUnknownBrowserId() {
            IllegalArgumentException thrown =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    extension.getWebDriver(
                                            "unknown-browser-id",
                                            DriverConfiguration.builder().requester(0).build()));

            assertThat(thrown.getMessage(), containsString("Unknown browser"));
        }

        @Test
        void shouldThrowWhenProxyAddressSetAndPortTooLow() {
            IllegalArgumentException thrown =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    extension.getWebDriver(
                                            "chrome",
                                            DriverConfiguration.builder()
                                                    .requester(0)
                                                    .proxyAddress("127.0.0.1")
                                                    .proxyPort(0)
                                                    .build()));

            assertThat(thrown.getMessage(), containsString("proxyPort"));
        }

        @Test
        void shouldThrowWhenProxyAddressSetAndPortTooHigh() {
            IllegalArgumentException thrown =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    extension.getWebDriver(
                                            "chrome",
                                            DriverConfiguration.builder()
                                                    .requester(0)
                                                    .proxyAddress("127.0.0.1")
                                                    .proxyPort(70000)
                                                    .build()));

            assertThat(thrown.getMessage(), containsString("proxyPort"));
        }

        @Test
        void shouldThrowWhenProxyAddressEmpty() {
            IllegalArgumentException thrown =
                    assertThrows(
                            IllegalArgumentException.class,
                            () ->
                                    extension.getWebDriver(
                                            "chrome",
                                            DriverConfiguration.builder()
                                                    .requester(0)
                                                    .proxyAddress("")
                                                    .proxyPort(8080)
                                                    .build()));

            assertThat(thrown.getMessage(), containsString("proxyAddress"));
        }
    }

    @Nested
    class AddAndRemoveCustomBrowser {

        private ExtensionSelenium extension;

        @BeforeEach
        void initExtension() throws Exception {
            extension = new ExtensionSelenium();
            extension.init();
            extension.getOptions().load(new ZapXmlConfiguration());
        }

        @Test
        void shouldThrowNullPointerExceptionWhenAddingNullBrowser() {
            assertThrows(NullPointerException.class, () -> extension.addCustomBrowser(null));
        }

        @Test
        void shouldThrowNullPointerExceptionWhenRemovingNullName() {
            assertThrows(NullPointerException.class, () -> extension.removeCustomBrowser(null));
        }

        @Test
        void shouldAddCustomBrowser() {
            CustomBrowser browser =
                    CustomBrowser.builder().name("TestBrowser").browserType("Chromium").build();

            extension.addCustomBrowser(browser);
            assertThat(
                    containsBrowserId(extension.getProvidedBrowserUIList(), "custom.TestBrowser"),
                    is(true));
            assertThat(
                    containsBrowserId(
                            extension.getProvidedBrowserUIList(), "custom.TestBrowser-headless"),
                    is(true));
        }

        private boolean containsBrowserId(List<ProvidedBrowserUI> list, String id) {
            return list.stream()
                    .anyMatch(
                            ui ->
                                    ui.getBrowser().getId().equals("custom.TestBrowser")
                                            || ui.getBrowser().getId().equals(id));
        }

        @Test
        void shouldRemoveCustomBrowser() {
            CustomBrowser browser =
                    CustomBrowser.builder().name("TestBrowser").browserType("Chromium").build();

            extension.addCustomBrowser(browser);

            boolean removed = extension.removeCustomBrowser("TestBrowser");
            assertThat(removed, is(true));
            assertThat(
                    containsBrowserId(extension.getProvidedBrowserUIList(), "custom.TestBrowser"),
                    is(false));
            assertThat(
                    containsBrowserId(
                            extension.getProvidedBrowserUIList(), "custom.TestBrowser-headless"),
                    is(false));
        }
    }

    @Nested
    class BrowserHooks {

        private ExtensionSelenium extension;

        @BeforeEach
        void initExtension() {
            extension = new ExtensionSelenium();
            extension.init();
        }

        @Test
        void shouldThrowNullPointerExceptionWhenRegisteringNullHook() {
            assertThrows(NullPointerException.class, () -> extension.registerBrowserHook(null));
        }

        @Test
        void shouldThrowNullPointerExceptionWhenDeregisteringNullHook() {
            assertThrows(NullPointerException.class, () -> extension.deregisterBrowserHook(null));
        }

        @Test
        void shouldNotCallHookAfterDeregistered() throws Exception {
            AtomicBoolean hookCalled = new AtomicBoolean(false);
            BrowserHook hook = ssu -> hookCalled.set(true);

            extension.registerBrowserHook(hook);
            WebDriver driver =
                    extension.getWebDriver(
                            "htmlunit", DriverConfiguration.builder().requester(0).build());
            try {
                assertThat(
                        "Hook should be called when browser is launched",
                        hookCalled.get(),
                        is(true));
            } finally {
                driver.quit();
            }

            hookCalled.set(false);
            extension.deregisterBrowserHook(hook);

            WebDriver driver2 =
                    extension.getWebDriver(
                            "htmlunit", DriverConfiguration.builder().requester(0).build());
            try {
                assertThat(
                        "Hook should not be called after deregistration",
                        hookCalled.get(),
                        is(false));
            } finally {
                driver2.quit();
            }
        }
    }

    @Nested
    class GetProfileManager {

        private ExtensionSelenium extension;

        @BeforeEach
        void initExtension() {
            extension = new ExtensionSelenium();
            extension.init();
        }

        @Test
        void shouldReturnProfileManagerForFirefox() {
            assertThat(extension.getProfileManager(Browser.FIREFOX), is(notNullValue()));
        }

        @Test
        void shouldReturnNullForChrome() {
            assertThat(extension.getProfileManager(Browser.CHROME), is(nullValue()));
        }

        @Test
        void shouldReturnNullForEdge() {
            assertThat(extension.getProfileManager(Browser.EDGE), is(nullValue()));
        }
    }
}
