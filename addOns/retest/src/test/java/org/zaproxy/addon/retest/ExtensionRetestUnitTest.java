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
package org.zaproxy.addon.retest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;

class ExtensionRetestUnitTest {

    private static final int PLUGIN_ID = 100;
    private static final String NAME = "Test Alert";
    private static final String URL = "https://www.example.com";
    private static final String METHOD = "GET";
    private static final String ATTACK = "Test Attack";
    private static final String PARAM = "Test Param";
    private static final String EVIDENCE = "Test Evidence";
    private static final String CONFIDENCE = "Test Confidence";
    private static final String RISK = "Test Risk";
    private static final String OTHER_INFO = "Test Other Info";

    @Test
    void shouldDependOnAutomation() {
        // Given / When
        ExtensionRetest extRetest = new ExtensionRetest();

        // Then
        assertThat(extRetest.getDependencies().size(), is(equalTo(1)));
        assertThat(extRetest.getDependencies().get(0), is(equalTo(ExtensionAutomation.class)));
    }

    @Test
    void shouldUnload() {
        // Given / When
        ExtensionRetest extRetest = new ExtensionRetest();

        // Then
        assertThat(extRetest.canUnload(), is(equalTo(true)));
    }

    @Nested
    class TestForAlert {
        private AutomationAlertTest test;
        private AlertData alertData;

        @BeforeEach
        void setup() {
            test = mock(AutomationAlertTest.class);
            AutomationAlertTest.Data testData = mock(AutomationAlertTest.Data.class);
            given(testData.getScanRuleId()).willReturn(PLUGIN_ID);
            given(testData.getAlertName()).willReturn(NAME);
            given(testData.getUrl()).willReturn(URL);
            given(testData.getMethod()).willReturn(METHOD);
            given(testData.getAttack()).willReturn(ATTACK);
            given(testData.getParam()).willReturn(PARAM);
            given(testData.getEvidence()).willReturn(EVIDENCE);
            given(testData.getConfidence()).willReturn(CONFIDENCE);
            given(testData.getRisk()).willReturn(RISK);
            given(testData.getOtherInfo()).willReturn(OTHER_INFO);
            given(test.getData()).willReturn(testData);

            alertData = new AlertData();
            alertData.setScanRuleId(PLUGIN_ID);
            alertData.setAlertName(NAME);
            alertData.setUrl(URL);
            alertData.setMethod(METHOD);
            alertData.setAttack(ATTACK);
            alertData.setParam(PARAM);
            alertData.setEvidence(EVIDENCE);
            alertData.setConfidence(CONFIDENCE);
            alertData.setRisk(RISK);
            alertData.setOtherInfo(OTHER_INFO);
        }

        @Test
        void shouldReturnTrueIfTestIsForAlert() {
            // Given / When
            boolean result = ExtensionRetest.testsForAlert(test, alertData);

            // Then
            assertThat(result, is(equalTo(true)));
        }

        @Test
        void shouldReturnFalseIfTestIsNotForAlert() {
            // Given
            alertData.setAlertName("Test Alert Two");

            // When
            boolean result = ExtensionRetest.testsForAlert(test, alertData);

            // Then
            assertThat(result, is(equalTo(false)));
        }
    }
}
