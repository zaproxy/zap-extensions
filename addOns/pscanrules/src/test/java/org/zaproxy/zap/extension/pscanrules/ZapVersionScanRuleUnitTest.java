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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.time.LocalDate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class ZapVersionScanRuleUnitTest extends PassiveScannerTest<ZapVersionScanRule> {

    LocalDate today = LocalDate.of(2025, 7, 10);

    @Override
    protected ZapVersionScanRule createScanner() {
        return new ZapVersionScanRule();
    }

    @Test
    void shouldHandleInvalidDateVersionStrings() {
        // Given / When / then
        assertThat(ZapVersionScanRule.getDateRisk("2020-01-01", today), is(equalTo(-1)));
        assertThat(ZapVersionScanRule.getDateRisk("d-2020-01-01", today), is(equalTo(-1)));
        assertThat(ZapVersionScanRule.getDateRisk("D_2020-01-01", today), is(equalTo(-1)));
        assertThat(ZapVersionScanRule.getDateRisk(null, today), is(equalTo(-1)));
        assertThat(ZapVersionScanRule.getDateRisk(null, null), is(equalTo(-1)));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "D-2030-03-29, -4",
                "D-2026-07-07, 0",
                "D-2025-07-06, 0",
                "D-2024-08-11, 0",
                "D-2024-07-30, 1",
                "D-2024-06-11, 1",
                "D-2020-01-01, 3",
                "D-2010-09-01, 3"
            })
    void shouldReturnExpectedDateRisks(String version, String riskStr) {
        assertThat(
                ZapVersionScanRule.getDateRisk(version, today),
                is(equalTo(Integer.parseInt(riskStr))));
    }

    @ParameterizedTest
    @CsvSource(
            value = {
                "2.18.1, 2.16.0, 0",
                "2.16.1, 2.16.0, 0",
                "2.15.0, 2.16.0, 1",
                "2.14.1, 2.16.0, 2",
                "2.16.1, 3.1.0, 2",
                "2.8.0, 2.16.0, 3",
                "2.16.1, 3.5.0, 3",
                "2.14.1, 2.17.0, 3"
            })
    void shouldReturnExpectedVersionRisks(
            String currentVersion, String latestVersion, String riskStr) {
        assertThat(
                ZapVersionScanRule.getVersionRisk(currentVersion, latestVersion),
                is(equalTo(Integer.parseInt(riskStr))));
    }
}
