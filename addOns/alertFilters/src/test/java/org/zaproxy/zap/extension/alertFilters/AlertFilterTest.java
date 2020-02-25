/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;

/** Unit test for {@link AlertFilter}. */
public class AlertFilterTest {

    private Alert alert;

    @Before
    public void before() throws Exception {
        alert = new Alert(1, Alert.RISK_INFO, Alert.CONFIDENCE_LOW, "Test alert");
        alert.setUri("https://www.example.com");
        alert.setParam("param");
        alert.setAttack("attack");
        alert.setEvidence("evidence");
    }

    @Test
    public void defaultEnabledFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void defaultDisabledFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(false);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void missingUriFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void differentUriFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("https://mozilla.org");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void matchingUriRegexFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("https://www.example.*");
        af.setUrlRegex(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void notMatchingUriRegexFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("https://www.other.*");
        af.setUrlRegex(true);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void missingParameterFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void differentParameterFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void matchingParameterRegexFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter(".*ram");
        af.setParameterRegex(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void notMatchingParameterRegexFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter(".*rammer");
        af.setParameterRegex(true);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void missingAttackFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void differentAttackFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void matchingAttackRegexFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack(".*ck");
        af.setAttackRegex(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void notMatchingAttackRegexFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack(".*cker");
        af.setAttackRegex(true);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void missingEvidenceFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void differentEvidenceFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    public void matchingEvidenceRegexFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("evi.*ce");
        af.setEvidenceRegex(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    public void notMatchingEvidenceRegexFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("evil.*ce");
        af.setEvidenceRegex(true);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }
}
