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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
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

    @Test
    void shouldSendFullCodeForSingleCombinedTotpField() {
        // Given
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);
        AuthenticationContext ctx = new AuthenticationContext();

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            totpMock.when(() -> TotpSupport.getCode(credentials)).thenReturn("654321");

            // When
            step.execute(wd, credentials, ctx);

            // Then - full TOTP code is sent to the single combined field
            verify(field).sendKeys("654321");
        }
    }

    @Test
    void shouldCacheTotpCodeInContextAcrossStepExecutions() {
        // Given - the same AuthenticationContext is reused across two execute calls
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);
        AuthenticationContext ctx = new AuthenticationContext();

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            totpMock.when(() -> TotpSupport.getCode(credentials)).thenReturn("654321");

            // When - execute twice with the same context
            step.execute(wd, credentials, ctx);
            step.execute(wd, credentials, ctx);

            // Then - TotpSupport is only called once; the code is served from cache on the second call
            totpMock.verify(() -> TotpSupport.getCode(credentials), times(1));
        }
    }

    @Test
    void shouldFallbackToStepGeneratorWhenTotpSupportReturnsNull() {
        // Given
        AuthenticationStep step = createTotpStep();
        WebElement field = mockField();
        WebDriver wd = mockWebDriver(field);
        UsernamePasswordAuthenticationCredentials credentials =
                mock(UsernamePasswordAuthenticationCredentials.class);
        AuthenticationContext ctx = new AuthenticationContext();

        try (MockedStatic<TotpSupport> totpMock = mockStatic(TotpSupport.class)) {
            totpMock.when(() -> TotpSupport.getCode(credentials)).thenReturn(null);

            // When
            step.execute(wd, credentials, ctx);

            // Then - a code is still sent via the step's own TOTPGenerator
            verify(field).sendKeys(anyString());
        }
    }
}
