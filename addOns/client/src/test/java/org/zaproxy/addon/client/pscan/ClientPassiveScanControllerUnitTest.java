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
package org.zaproxy.addon.client.pscan;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Unit test for {@link ClientPassiveScanController}. */
class ClientPassiveScanControllerUnitTest {

    private ClientPassiveScanController pscanController;

    @BeforeEach
    void setUp() {
        pscanController = new ClientPassiveScanController();
    }

    @Test
    void shouldInitWithTheRightDefaults() {
        // Given / When / Then
        assertThat(pscanController.isEnabled(), is(true));
        assertThat(pscanController.getAllScanRules().size(), is(3));
        assertThat(
                pscanController.getAllScanRules().get(0).getClass(),
                is(InformationInStorageScanRule.class));
        assertThat(
                pscanController.getAllScanRules().get(1).getClass(),
                is(SensitiveInfoInStorageScanRule.class));
        assertThat(
                pscanController.getAllScanRules().get(2).getClass(),
                is(JwtInStorageScanRule.class));
        assertThat(pscanController.getDisabledScanRules().size(), is(0));
        assertThat(pscanController.getEnabledScanRules().size(), is(3));
        assertThat(
                pscanController.getEnabledScanRules().get(0).getClass(),
                is(InformationInStorageScanRule.class));
        assertThat(
                pscanController.getEnabledScanRules().get(1).getClass(),
                is(SensitiveInfoInStorageScanRule.class));
        assertThat(
                pscanController.getEnabledScanRules().get(2).getClass(),
                is(JwtInStorageScanRule.class));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetEnabled(boolean enabled) {
        // Given
        pscanController.setEnabled(!enabled);
        // When
        pscanController.setEnabled(enabled);
        // Then
        assertThat(pscanController.isEnabled(), is(enabled));
    }

    @Test
    void shouldReturnNoScannersIfDisabled() {
        // Given / When
        pscanController.setEnabled(false);
        // Then
        assertThat(pscanController.getEnabledScanRules().size(), is(0));
    }

    @Test
    void shouldDisableAllScannersWithEmptyEnableList() {
        // Given / When
        pscanController.setEnabledScanRules(List.of());
        // Then
        assertThat(pscanController.getEnabledScanRules().size(), is(0));
    }

    @Test
    void shouldEnableScannersUsingList() {
        // Given
        pscanController.setEnabledScanRules(new ArrayList<>());
        // When
        pscanController.setEnabledScanRules(
                Arrays.asList(pscanController.getAllScanRules().get(0)));

        // Then
        assertThat(pscanController.getEnabledScanRules().size(), is(1));
        assertThat(
                pscanController.getEnabledScanRules().get(0).getClass(),
                is(InformationInStorageScanRule.class));
    }

    @Test
    void shouldDisableScannersUsingList() {
        // Given / When
        pscanController.setDisabledScanRules(Arrays.asList(120000));

        // Then
        assertThat(pscanController.getEnabledScanRules().size(), is(2));
        assertThat(
                pscanController.getEnabledScanRules().get(0).getClass(),
                is(SensitiveInfoInStorageScanRule.class));
        assertThat(pscanController.getDisabledScanRules().size(), is(1));
        assertThat(
                pscanController.getDisabledScanRules().get(0).getClass(),
                is(InformationInStorageScanRule.class));
    }
}
