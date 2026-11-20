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
package org.zaproxy.addon.clienttest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;

/** Unit test for {@link LaunchCheck}. */
class LaunchCheckUnitTest {

    private interface TestWebDriver extends WebDriver, JavascriptExecutor {}

    private final TestWebDriver driver = mock(TestWebDriver.class);

    @Test
    void shouldReportConfiguredExtension() {
        // Given
        given(driver.executeScript(LaunchCheck.EXTENSION_CONFIGURED_SCRIPT)).willReturn("true");
        // When
        String configured = LaunchCheck.isExtensionConfigured(driver);
        // Then
        assertThat(configured, is("true"));
    }

    @Test
    void shouldReportNotConfiguredExtension() {
        // Given
        given(driver.executeScript(LaunchCheck.EXTENSION_CONFIGURED_SCRIPT)).willReturn(null);
        // When
        String configured = LaunchCheck.isExtensionConfigured(driver);
        // Then
        assertThat(configured, is("null"));
    }

    @Test
    void shouldReportErrorReadingConfiguration() {
        // Given
        given(driver.executeScript(anyString()))
                .willThrow(
                        new WebDriverException("SecurityError: The operation is insecure.\nmore"));
        // When
        String configured = LaunchCheck.isExtensionConfigured(driver);
        // Then
        assertThat(configured, startsWith("error: SecurityError: The operation is insecure."));
    }
}
