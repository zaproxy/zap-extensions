/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.commonlib.internal.TotpSupport;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

/** Unit tests for TOTP field execution in {@link AuthenticationStep}. */
class AuthenticationStepUnitTest {

    private static AuthenticationStep createTotpStep() {
        AuthenticationStep step = new AuthenticationStep();
        step.setType(AuthenticationStep.Type.TOTP_FIELD);
        step.setCssSelector("#otp");
        step.setTimeout(1000);
        step.setTotpSecret("JBSWY3DPEHPK3PXP");
        step.setTotpPeriod(30);
        step.setTotpDigits(6);
        step.setTotpAlgorithm("SHA1");
        return step;
    }

    private static WebDriver mockWebDriver(WebElement element) {
        WebDriver wd = mock(WebDriver.class);
        given(wd.findElement(any())).willReturn(element);
        return wd;
    }

    private static WebElement mockField() {
        WebElement field = mock(WebElement.class);
        given(field.getAttribute(anyString())).willReturn(null);
        return field;
    }

    @ParameterizedTest
    @CsvSource({"0,1", "1,2", "2,3", "3,4", "4,5", "5,6"})
    void shouldSendSingleCharToEachSplitTotpField(int charIndex, String expectedChar) {
        // Given
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);

        // When - precomputed code + charIndex selects the correct digit
        step.execute(wd, credentials, charIndex, "123456");

        // Then - only the single digit at charIndex is sent
        verify(field).sendKeys(expectedChar);
    }

    @Test
    void shouldSendFullCodeForSingleCombinedTotpField() {
        // Given
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            totpMock.when(() -> TotpSupport.getCode(credentials)).thenReturn("654321");

            // When - charIndex=-1 means single combined field, send full code
            step.execute(wd, credentials, -1, null);

            // Then - full TOTP code is sent
            verify(field).sendKeys("654321");
        }
    }

    @Test
    void shouldUsePrecomputedCodeWithoutCallingTotpSupport() {
        // Given - precomputedTotpCode is already available
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            // When - precomputedTotpCode is provided; TotpSupport should NOT be called
            step.execute(wd, credentials, 0, "123456");

            // Then
            totpMock.verify(() -> TotpSupport.getCode(any()), never());
            verify(field).sendKeys("1");
        }
    }

    @Test
    void shouldFallbackToTotpSupportWhenNoPrecomputedCode() {
        // Given
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            totpMock.when(() -> TotpSupport.getCode(credentials)).thenReturn("112233");

            // When - no precomputed code, charIndex=2 → use TotpSupport.getCode()
            step.execute(wd, credentials, 2, null);

            // Then - 3rd digit of "112233" is "2"
            verify(field).sendKeys("2");
        }
    }
}
