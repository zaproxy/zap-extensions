/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper;

import static org.junit.Assert.assertEquals;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner.IndicatorStatus.COULD_NOT_VERIFY;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner.IndicatorStatus.FOUND;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner.IndicatorStatus.NOT_DEFINED;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner.IndicatorStatus.NOT_FOUND;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus.CONFLICTING;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus.FAILED;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus.SUCCESSFULL;
import static org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus.UNKNOWN;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusScanner.IndicatorStatus;
import org.zaproxy.zap.extension.authenticationhelper.statusscan.AuthenticationStatusTableEntry.AuthenticationStatus;

public class AuthenticationStatusScannerTest {

    private AuthenticationStatusScanner statusScanner;

    private AuthenticationStatus actualAuthStatus;
    private AuthenticationStatus expectedAuthStatus;
    private IndicatorStatus inIndicator;
    private IndicatorStatus outIndicator;

    @Rule public ExpectedException exceptionRule = ExpectedException.none();

    @Before
    public void setUp() {
        statusScanner = Mockito.mock(AuthenticationStatusScanner.class, Mockito.CALLS_REAL_METHODS);
    }

    @Test
    public void testDetermineAuthenticationStatus() {

        // ================ combination 01 of 10 ================

        // Given
        inIndicator = FOUND;
        outIndicator = FOUND;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = CONFLICTING;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 02 of 10 ================

        // Given
        inIndicator = FOUND;
        outIndicator = NOT_FOUND;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = SUCCESSFULL;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 03 of 10 ================

        // Given
        inIndicator = FOUND;
        outIndicator = NOT_DEFINED;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = SUCCESSFULL;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 04 of 10 ================

        // Given
        inIndicator = FOUND;
        outIndicator = COULD_NOT_VERIFY;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = FAILED;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 05 of 10 ================

        // Given
        inIndicator = NOT_FOUND;
        outIndicator = NOT_FOUND;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = UNKNOWN;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 06 of 10 ================

        // Given
        inIndicator = NOT_FOUND;
        outIndicator = NOT_DEFINED;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = FAILED;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 07 of 10 ================

        // Given
        inIndicator = NOT_FOUND;
        outIndicator = COULD_NOT_VERIFY;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = FAILED;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 08 of 10 ================

        // Given
        inIndicator = NOT_DEFINED;
        outIndicator = COULD_NOT_VERIFY;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = FAILED;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);

        // ================ combination 09 of 10 ================

        // Given
        inIndicator = COULD_NOT_VERIFY;
        outIndicator = COULD_NOT_VERIFY;

        // When
        actualAuthStatus = statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);

        // Then
        expectedAuthStatus = FAILED;
        assertStatus(inIndicator, outIndicator, expectedAuthStatus, actualAuthStatus);
    }

    @Test
    public void shouldThrowIllegalArgumentExceptionIfBothIndicatorsAreNotDefined() {
        // ================ combination 10 of 10 ================

        // Given
        inIndicator = NOT_DEFINED;
        outIndicator = NOT_DEFINED;

        // Then/When
        exceptionRule.expect(IllegalArgumentException.class);
        exceptionRule.expectMessage(
                "atleast one of logged in or logged out indicator should be defined");
        statusScanner.determineAuthenticationStatus(inIndicator, outIndicator);
    }

    private void assertStatus(
            IndicatorStatus inIndicator,
            IndicatorStatus outIndicator,
            AuthenticationStatus expectedAuthStatus,
            AuthenticationStatus actualAuthStatus) {
        assertEquals(
                "inIndicator -> " + inIndicator + ", outIndicator -> " + outIndicator,
                expectedAuthStatus,
                actualAuthStatus);
    }
}
