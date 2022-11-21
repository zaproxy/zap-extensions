/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Locale;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.parosproxy.paros.core.scanner.Alert;

class SarifLevelUnitTest {

    @ParameterizedTest(name = "Risk level {0} is mapped to {1}")
    @CsvSource({
        Alert.RISK_HIGH + ",ERROR",
        Alert.RISK_MEDIUM + ",WARNING",
        Alert.RISK_LOW + ",NOTE",
        Alert.RISK_INFO + ",NONE"
    })
    void fromAlertAcceptsAlertsHavingRiskLevelsFromAlertConstants(int alertRisk, String enumName) {
        /* prepare */
        SarifLevel expectedSarifLevel = SarifLevel.valueOf(enumName);

        /* execute */
        SarifLevel toTest = SarifLevel.fromAlertRisk(alertRisk);

        /* test */
        assertEquals(expectedSarifLevel, toTest);
    }

    @ParameterizedTest(name = "Sarif level {0} has value as lowerecased")
    @EnumSource(value = SarifLevel.class)
    void getValueJustRepresentsLowerCasedNameOfEnum(SarifLevel level) {
        assertEquals(level.name().toLowerCase(Locale.ROOT), level.getValue());
    }
}
