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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/** Unit test for {@link AlertFilter}. */
class AlertFilterUnitTest {

    private static final int SCAN_RULE_ID = 420;
    private static final String ALERT_REF = SCAN_RULE_ID + "-2";
    private static final String ALERT_METHOD = "PATCH";
    private static final int NO_CONTEXT = -1;

    private Alert alert;

    @BeforeEach
    void before() throws Exception {
        alert = new Alert(SCAN_RULE_ID, Alert.RISK_INFO, Alert.CONFIDENCE_LOW, "Test alert");
        alert.setAlertRef(ALERT_REF);
        String uri = "https://www.example.com";
        alert.setUri(uri);
        alert.setParam("param");
        alert.setAttack("attack");
        alert.setEvidence("evidence");
        alert.setMessage(
                new HttpMessage(new HttpRequestHeader(ALERT_METHOD + " " + uri + " HTTP/1.1")));
    }

    @Test
    void shouldUseScanRuleIdFromAlert() {
        // Given
        int scanRuleId = 1234;
        alert = Alert.builder().setPluginId(scanRuleId).build();
        // When
        AlertFilter af = new AlertFilter(NO_CONTEXT, alert);
        // Then
        assertThat(af.getRuleId(), is(equalTo(String.valueOf(scanRuleId))));
    }

    @Test
    void shouldUseAlertRefFromAlert() {
        // Given
        String alertRef = "0-123";
        alert = Alert.builder().setAlertRef(alertRef).build();
        // When
        AlertFilter af = new AlertFilter(NO_CONTEXT, alert);
        // Then
        assertThat(af.getRuleId(), is(equalTo(alertRef)));
    }

    @Test
    void shouldApplyByScanRuleId() {
        // Given
        AlertFilter af = new AlertFilter();
        af.setEnabled(true);
        af.setRuleId(String.valueOf(SCAN_RULE_ID));
        // When
        boolean applies = af.appliesToAlert(alert, true);
        // Then
        assertThat(applies, is(equalTo(true)));
    }

    @Test
    void shouldNotApplyByScanRuleIdIfDifferent() {
        // Given
        AlertFilter af = new AlertFilter();
        af.setEnabled(true);
        af.setRuleId(String.valueOf(SCAN_RULE_ID - 1));
        // When
        boolean applies = af.appliesToAlert(alert, true);
        // Then
        assertThat(applies, is(equalTo(false)));
    }

    @Test
    void shouldApplyByAlertRef() {
        // Given
        AlertFilter af = new AlertFilter();
        af.setEnabled(true);
        af.setRuleId(ALERT_REF);
        // When
        boolean applies = af.appliesToAlert(alert, true);
        // Then
        assertThat(applies, is(equalTo(true)));
    }

    @Test
    void shouldNotApplyByAlertRefIfDifferent() {
        // Given
        AlertFilter af = new AlertFilter();
        af.setEnabled(true);
        af.setRuleId(ALERT_REF + "-8");
        // When
        boolean applies = af.appliesToAlert(alert, true);
        // Then
        assertThat(applies, is(equalTo(false)));
    }

    @Test
    void defaultEnabledFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    void defaultDisabledFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(false);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void missingUriFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    void differentUriFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setUrl("https://mozilla.org");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void matchingUriRegexFilterMatches() {
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
    void notMatchingUriRegexFilterDoesNotMatch() {
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
    void missingParameterFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    void differentParameterFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setParameter("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void matchingParameterRegexFilterMatches() {
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
    void notMatchingParameterRegexFilterDoesNotMatch() {
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
    void missingAttackFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    void differentAttackFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setAttack("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void matchingAttackRegexFilterMatches() {
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
    void notMatchingAttackRegexFilterDoesNotMatch() {
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
    void missingEvidenceFilterMatches() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("");
        // Then
        assertTrue(af.appliesToAlert(alert));
    }

    @Test
    void differentEvidenceFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("different");
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void matchingEvidenceRegexFilterMatches() {
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
    void notMatchingEvidenceRegexFilterDoesNotMatch() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        // When
        af.setEnabled(true);
        af.setEvidence("evil.*ce");
        af.setEvidenceRegex(true);
        // Then
        assertFalse(af.appliesToAlert(alert));
    }

    @Test
    void shouldNormaliseCaseMethodsSet() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        Set<String> methods = set("Get", "post");
        // When
        af.setMethods(methods);
        // Then
        assertThat(af.getMethods(), containsInAnyOrder("GET", "POST"));
    }

    @Test
    void shouldIgnoreNullAndEmpyMethodsSet() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        Set<String> methods = set(null, "GET", "");
        // When
        af.setMethods(methods);
        // Then
        assertThat(af.getMethods(), contains("GET"));
    }

    @Test
    void shouldApplyWithNoMethods() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        af.setMethods(set());
        // When
        boolean applies = af.appliesToAlert(alert);
        // Then
        assertThat(applies, is(equalTo(true)));
    }

    @Test
    void shouldApplyWithEqualMethod() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        af.setMethods(set(ALERT_METHOD, "OTHER_METHOD"));
        // When
        boolean applies = af.appliesToAlert(alert);
        // Then
        assertThat(applies, is(equalTo(true)));
    }

    @Test
    void shouldNotApplyWithDifferentMethod() {
        // Given
        AlertFilter af = new AlertFilter(-1, alert);
        af.setMethods(set("NOT_" + ALERT_METHOD, "OTHER_METHOD"));
        // When
        boolean applies = af.appliesToAlert(alert);
        // Then
        assertThat(applies, is(equalTo(false)));
    }

    private static Set<String> set(String... strings) {
        return new HashSet<>(Arrays.asList(strings));
    }
}
