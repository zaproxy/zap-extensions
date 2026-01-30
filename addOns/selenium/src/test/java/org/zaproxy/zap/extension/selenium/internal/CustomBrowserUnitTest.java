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
package org.zaproxy.zap.extension.selenium.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link CustomBrowserImpl}. */
class CustomBrowserUnitTest extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionSelenium());
    }

    @Test
    void shouldCreateWithDefaultValues() {
        // Given / When
        CustomBrowserImpl browser = new CustomBrowserImpl();
        // Then
        assertThat(browser.getName(), is(equalTo("")));
        assertThat(browser.getDriverPath(), is(equalTo("")));
        assertThat(browser.getBinaryPath(), is(equalTo("")));
        assertThat(browser.getBrowserType(), is(equalTo(CustomBrowserImpl.BrowserType.CHROMIUM)));
        assertThat(browser.getArguments(), is(notNullValue()));
        assertThat(browser.getArguments().isEmpty(), is(equalTo(true)));
        assertThat(browser.isBuiltIn(), is(equalTo(false)));
    }

    @Test
    void shouldCreateWithGivenValues() {
        // Given
        String name = "TestBrowser";
        String driverPath = "/path/to/driver";
        String binaryPath = "/path/to/binary";
        CustomBrowserImpl.BrowserType browserType = CustomBrowserImpl.BrowserType.FIREFOX;
        List<BrowserArgument> arguments = new ArrayList<>();
        arguments.add(new BrowserArgument("--arg1", true));
        // When
        CustomBrowserImpl browser =
                new CustomBrowserImpl(name, driverPath, binaryPath, browserType, arguments);
        // Then
        assertThat(browser.getName(), is(equalTo(name)));
        assertThat(browser.getDriverPath(), is(equalTo(driverPath)));
        assertThat(browser.getBinaryPath(), is(equalTo(binaryPath)));
        assertThat(browser.getBrowserType(), is(equalTo(browserType)));
        assertThat(browser.getArguments(), hasSize(1));
        assertThat(browser.getArguments().get(0).getArgument(), is(equalTo("--arg1")));
    }

    @Test
    void shouldThrowWhenCreatingWithNullName() {
        // Given
        String name = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () ->
                        new CustomBrowserImpl(
                                name,
                                "",
                                "",
                                CustomBrowserImpl.BrowserType.CHROMIUM,
                                new ArrayList<>()));
    }

    @Test
    void shouldThrowWhenCreatingWithNullBrowserType() {
        // Given
        CustomBrowserImpl.BrowserType browserType = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () -> new CustomBrowserImpl("Test", "", "", browserType, new ArrayList<>()));
    }

    @Test
    void shouldCreateCopyFromOtherBrowser() {
        // Given
        CustomBrowserImpl original =
                new CustomBrowserImpl(
                        "Test",
                        "/driver",
                        "/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        original.setBuiltIn(true);
        // When
        CustomBrowserImpl copy = new CustomBrowserImpl(original);
        // Then
        assertThat(copy.getName(), is(equalTo(original.getName())));
        assertThat(copy.getDriverPath(), is(equalTo(original.getDriverPath())));
        assertThat(copy.getBinaryPath(), is(equalTo(original.getBinaryPath())));
        assertThat(copy.getBrowserType(), is(equalTo(original.getBrowserType())));
        assertThat(copy.isBuiltIn(), is(equalTo(original.isBuiltIn())));
    }

    @Test
    void shouldSetNameTrimmed() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        String name = "  TestBrowser  ";
        // When
        browser.setName(name);
        // Then
        assertThat(browser.getName(), is(equalTo("TestBrowser")));
    }

    @Test
    void shouldThrowWhenSettingNullName() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        // When / Then
        assertThrows(NullPointerException.class, () -> browser.setName(null));
    }

    @Test
    void shouldThrowWhenSettingNullBrowserType() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        // When / Then
        assertThrows(NullPointerException.class, () -> browser.setBrowserType(null));
    }

    @Test
    void shouldReturnI18nNameForChromiumBrowserType() {
        // Given / When
        String name = CustomBrowserImpl.BrowserType.CHROMIUM.toString();
        // Then
        assertThat(name, is(notNullValue()));
        assertThat(
                name,
                is(
                        equalTo(
                                Constant.messages.getString(
                                        "selenium.options.custom.browsers.type.chromium"))));
    }

    @Test
    void shouldReturnI18nNameForFirefoxBrowserType() {
        // Given / When
        String name = CustomBrowserImpl.BrowserType.FIREFOX.toString();
        // Then
        assertThat(name, is(notNullValue()));
        assertThat(
                name,
                is(
                        equalTo(
                                Constant.messages.getString(
                                        "selenium.options.custom.browsers.type.firefox"))));
    }

    @Test
    void shouldBeConfiguredWhenBuiltIn() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        browser.setBuiltIn(true);
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(true)));
    }

    @Test
    void shouldBeConfiguredWhenDriverAndBinaryPathsAreNotEmpty() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        browser.setDriverPath("/path/to/driver");
        browser.setBinaryPath("/path/to/binary");
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(true)));
    }

    @Test
    void shouldNotBeConfiguredWhenDriverPathIsEmpty() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        browser.setDriverPath("");
        browser.setBinaryPath("/path/to/binary");
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(false)));
    }

    @Test
    void shouldNotBeConfiguredWhenBinaryPathIsEmpty() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        browser.setDriverPath("/path/to/driver");
        browser.setBinaryPath("");
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(false)));
    }

    @Test
    void shouldNotBeConfiguredWhenBothPathsAreEmpty() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        browser.setDriverPath("");
        browser.setBinaryPath("");
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(false)));
    }

    @Test
    void shouldNotBeConfiguredWhenDriverPathIsNull() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test",
                        "",
                        "/path/to/binary",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(false)));
    }

    @Test
    void shouldNotBeConfiguredWhenBinaryPathIsNull() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test",
                        "/path/to/driver",
                        "",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        // When / Then
        assertThat(browser.isConfigured(), is(equalTo(false)));
    }

    @Test
    void shouldReturnCopyOfArguments() {
        // Given
        List<BrowserArgument> originalArgs = new ArrayList<>();
        originalArgs.add(new BrowserArgument("--arg1", true));
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, originalArgs);
        // When
        List<BrowserArgument> returnedArgs = browser.getArguments();
        returnedArgs.add(new BrowserArgument("--arg2", false));
        // Then
        assertThat(browser.getArguments(), hasSize(1));
        assertThat(returnedArgs, hasSize(2));
    }

    @Test
    void shouldSetArgumentsAsCopy() {
        // Given
        CustomBrowserImpl browser = new CustomBrowserImpl();
        List<BrowserArgument> args = new ArrayList<>();
        args.add(new BrowserArgument("--arg1", true));
        // When
        browser.setArguments(args);
        args.add(new BrowserArgument("--arg2", false));
        // Then
        assertThat(browser.getArguments(), hasSize(1));
        assertThat(args, hasSize(2));
    }

    @Test
    void shouldBeEqualToItself() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, new ArrayList<>());
        // When / Then
        assertThat(browser.equals(browser), is(equalTo(true)));
    }

    @Test
    void shouldBeEqualToDifferentBrowserWithSameName() {
        // Given
        CustomBrowserImpl browser1 =
                new CustomBrowserImpl(
                        "Test",
                        "/driver1",
                        "/binary1",
                        CustomBrowserImpl.BrowserType.CHROMIUM,
                        new ArrayList<>());
        CustomBrowserImpl browser2 =
                new CustomBrowserImpl(
                        "Test",
                        "/driver2",
                        "/binary2",
                        CustomBrowserImpl.BrowserType.FIREFOX,
                        new ArrayList<>());
        // When / Then
        assertThat(browser1.equals(browser2), is(equalTo(true)));
    }

    @Test
    void shouldNotBeEqualToNull() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, new ArrayList<>());
        // When / Then
        assertThat(browser.equals(null), is(equalTo(false)));
    }

    @Test
    void shouldNotBeEqualToDifferentBrowserWithDifferentName() {
        // Given
        CustomBrowserImpl browser1 =
                new CustomBrowserImpl(
                        "Test1", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, new ArrayList<>());
        CustomBrowserImpl browser2 =
                new CustomBrowserImpl(
                        "Test2", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, new ArrayList<>());
        // When / Then
        assertThat(browser1.equals(browser2), is(equalTo(false)));
    }

    @Test
    void shouldProduceConsistentHashCode() {
        // Given
        CustomBrowserImpl browser =
                new CustomBrowserImpl(
                        "Test", "", "", CustomBrowserImpl.BrowserType.CHROMIUM, new ArrayList<>());
        // When
        int hashCode1 = browser.hashCode();
        int hashCode2 = browser.hashCode();
        // Then
        assertThat(hashCode1, is(equalTo(hashCode2)));
    }
}
