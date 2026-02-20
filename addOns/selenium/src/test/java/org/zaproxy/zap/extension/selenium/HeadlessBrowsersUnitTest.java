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

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.quality.Strictness;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * Unit tests that verify Chrome, Edge, and Firefox headless browsers can be launched and access a
 * simple web page.
 */
@DisabledOnOs(OS.WINDOWS) // To prevent this failing in CICD
class HeadlessBrowsersUnitTest extends TestUtils {

    private static final String PAGE_TITLE = "Test Page";
    private static final String PAGE_BODY_MARKER = "Headless browser test content";

    private static final String IMAGE_PATH = "/test.png";
    private static final String PAGE_WITH_IMAGE_PATH = "/page-with-image.html";

    // These env vars should be set up when running in GitHub CI
    private static final String CHROME_WEB_DRIVER = System.getenv("CHROMEWEBDRIVER");
    private static final String GECKO_WEB_DRIVER = System.getenv("GECKOWEBDRIVER");

    private static final boolean IS_CICD = CHROME_WEB_DRIVER != null;

    private static ExtensionNetwork extensionNetwork;
    private static Model model;
    private static Session session;

    private WebDriver driver;

    @BeforeAll
    static void setupAll() {
        if (CHROME_WEB_DRIVER == null) {
            // Assume we are running locally
            String webdriversHome = System.getProperty("zap.test.webdrivers.home");
            if (webdriversHome != null && !webdriversHome.isEmpty()) {
                Browser.setZapHomeDir(Paths.get(webdriversHome));
            }
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        ExtensionSelenium extensionSelenium = new ExtensionSelenium();
        mockMessages(extensionSelenium);
        setUpZap();
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        Model.setSingletonForTesting(model);

        OptionsParam options = new OptionsParam();
        options.load(new ZapXmlConfiguration());
        given(model.getOptionsParam()).willReturn(options);

        extensionNetwork = new ExtensionNetwork();
        extensionNetwork.initModel(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);

        given(extensionLoader.getExtension(ExtensionSelenium.class)).willReturn(extensionSelenium);
        extensionSelenium.init();

        SeleniumOptions selOptions = extensionSelenium.getOptions();
        options.addParamSet(selOptions);

        extensionNetwork.init();
        extensionNetwork.hook(new ExtensionHook(model, null));

        if (CHROME_WEB_DRIVER != null) {
            selOptions.setChromeDriverPath(CHROME_WEB_DRIVER + "/chromedriver");
            selOptions.setEdgeDriverPath(CHROME_WEB_DRIVER + "/chromedriver");
        }
        if (GECKO_WEB_DRIVER != null) {
            selOptions.setFirefoxDriverPath(GECKO_WEB_DRIVER + "/geckodriver");
        }

        session = new Session(model);
        given(model.getSession()).willReturn(session);

        extensionSelenium.addCustomBrowser(new CustomBrowser("fx", null, null, null, "Firefox"));
        extensionSelenium.addCustomBrowser(new CustomBrowser("cr", null, null, null, "Chromium"));

        startServer();
        byte[] imageBytes =
                Files.readAllBytes(
                        TestUtils.getResourcePath(HeadlessBrowsersUnitTest.class, "test.png"));
        // More specific paths first (server matches by uri.startsWith(handler.getName()))
        nano.addHandler(
                new NanoServerHandler(IMAGE_PATH) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                NanoHTTPD.Response.Status.OK,
                                "image/png",
                                new ByteArrayInputStream(imageBytes),
                                imageBytes.length);
                    }
                });
        nano.addHandler(
                new NanoServerHandler(PAGE_WITH_IMAGE_PATH) {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String html =
                                "<html><head><title>Page With Image</title></head><body>"
                                        + "<img src=\"http://localhost:"
                                        + nano.getListeningPort()
                                        + IMAGE_PATH
                                        + "\" alt=\"test\"></body></html>";
                        return newFixedLengthResponse(html);
                    }
                });
        nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse(
                                "<html><head><title>"
                                        + PAGE_TITLE
                                        + "</title></head><body>"
                                        + PAGE_BODY_MARKER
                                        + "</body></html>");
                    }
                });
    }

    @AfterEach
    void tearDown() throws Exception {
        stopServer();
        Browser.setZapHomeDir(null);
        extensionNetwork.stop();
        if (driver != null) {
            driver.quit();
        }
    }

    static Stream<String> headlessBrowsers() {
        return Stream.concat(chromiumHeadlessBrowsers(), firefoxHeadlessBrowsers());
    }

    static Stream<String> firefoxHeadlessBrowsers() {
        return Stream.of("firefox-headless", "custom.fx-headless");
    }

    static Stream<String> chromiumHeadlessBrowsers() {
        if (IS_CICD) {
            // Have not been able to get edge to work in CICD so far
            return Stream.of("chrome-headless", "custom.cr-headless");
        }
        return Stream.of("chrome-headless", "edge-headless", "custom.cr-headless");
    }

    @ParameterizedTest
    @MethodSource("headlessBrowsers")
    void shouldAccessSimpleWebPageWithHeadlessBrowser(String browserId) throws IOException {
        ExtensionSelenium extensionSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        String url = "http://localhost:" + nano.getListeningPort() + "/";
        driver = extensionSelenium.getWebDriver(browserId, DriverConfiguration.builder().build());
        driver.get(url);

        assertThat(driver.getTitle(), is(PAGE_TITLE));
        assertThat(driver.getPageSource(), containsString(PAGE_BODY_MARKER));
    }

    @ParameterizedTest
    @MethodSource("headlessBrowsers")
    void shouldRequestImageWhenPageContainsImage(String browserId) throws IOException {
        ExtensionSelenium extensionSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        String url = "http://localhost:" + nano.getListeningPort() + PAGE_WITH_IMAGE_PATH;

        driver = extensionSelenium.getWebDriver(browserId, DriverConfiguration.builder().build());
        driver.get(url);

        assertThat(
                "Browser should request the image when loading the page",
                nano.getRequestedUris().contains(IMAGE_PATH),
                is(true));
    }

    /**
     * Returns browser preferences that disable image loading. Chrome/Edge use the same Chromium
     * pref ({@code profile.default_content_setting_values.images} = 2). Firefox uses {@code
     * permissions.default.image} = 2 (may not work in all Firefox versions).
     */
    private static Map<String, String> getPreferencesToBlockImages(String browserId) {
        if (browserId.startsWith("firefox") || browserId.startsWith("custom.fx")) {
            return Map.of("permissions.default.image", "2");
        }
        return Map.of("profile.default_content_setting_values.images", "2");
    }

    @ParameterizedTest
    @MethodSource("headlessBrowsers")
    void shouldNotRequestImageWhenPreferenceBlocksImages(String browserId) throws IOException {
        ExtensionSelenium extensionSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        String url = "http://localhost:" + nano.getListeningPort() + PAGE_WITH_IMAGE_PATH;
        Map<String, String> blockImagesPrefs = getPreferencesToBlockImages(browserId);

        driver =
                extensionSelenium.getWebDriver(
                        browserId,
                        DriverConfiguration.builder().preferences(blockImagesPrefs).build());
        driver.get(url);

        assertThat(
                "Browser should not request the image when prefs block images",
                nano.getRequestedUris().contains(IMAGE_PATH),
                is(false));
    }

    @ParameterizedTest
    @MethodSource("chromiumHeadlessBrowsers")
    /** Chrome and Edge only; Firefox does not support --user-agent as a command-line argument. */
    void shouldUseCustomUserAgentWhenArgumentSet(String browserId) throws IOException {
        String customUserAgent = "ZAP-Headless-Test-UA";
        ExtensionSelenium extensionSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        String url = "http://localhost:" + nano.getListeningPort() + "/";
        driver =
                extensionSelenium.getWebDriver(
                        browserId,
                        DriverConfiguration.builder()
                                .arguments(List.of("--user-agent=" + customUserAgent))
                                .build());
        driver.get(url);

        String userAgent =
                (String) ((JavascriptExecutor) driver).executeScript("return navigator.userAgent;");
        assertThat(
                "Browser should use the custom user-agent argument",
                userAgent,
                is(customUserAgent));
    }
}
