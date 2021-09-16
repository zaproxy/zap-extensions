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
package org.zaproxy.addon.automation.tests;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.ActiveScanJobResultData;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

public class AutomationAlertTestUnitTest extends TestUtils {

    private final String name = "example name";
    private final Integer scanRuleId = 100;
    private final String onFail = "warn";
    private LinkedHashMap<String, Object> testData = new LinkedHashMap<>();
    private ActiveScanJobResultData data;
    private Alert alert;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        ExtensionAlert extensionAlert = mock(ExtensionAlert.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
        given(extensionLoader.getExtension(ExtensionAlert.class)).willReturn(extensionAlert);
        data = mock(ActiveScanJobResultData.class);
        given(data.getKey()).willReturn("activeScanData");
        alert = new Alert(scanRuleId);
        alert.setAlertId(1);
        testData.put("scanRuleId", scanRuleId);
        testData.put("name", name);
        testData.put(AutomationAlertTest.PARAM_ON_FAIL, onFail);
    }

    private static Stream<Arguments> shouldReturnValuesForMatching() {
        return Stream.of(
                Arguments.of(AutomationAlertTest.PARAM_ALERT_NAME, "exampleAlertName"),
                Arguments.of(AutomationAlertTest.PARAM_URL, "http://www.example.com"),
                Arguments.of(AutomationAlertTest.PARAM_METHOD, "GET"),
                Arguments.of(AutomationAlertTest.PARAM_ATTACK, "exampleAttack"),
                Arguments.of(AutomationAlertTest.PARAM_PARAM, "exampleParam"),
                Arguments.of(AutomationAlertTest.PARAM_EVIDENCE, "exampleEvidence"),
                Arguments.of(AutomationAlertTest.PARAM_CONFIDENCE, "0"),
                Arguments.of(AutomationAlertTest.PARAM_RISK, "1"),
                Arguments.of(AutomationAlertTest.PARAM_OTHER_INFO, "exampleOtherInfo"));
    }

    @ParameterizedTest
    @MethodSource("shouldReturnValuesForMatching")
    void shouldPassOnPresentAlertWithPassIfPresentAndIfSpecifiedValuesMatch(
            String key, String value) {
        // Given
        String action = "passIfPresent";
        testData.put(AutomationAlertTest.PARAM_ACTION, action);

        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        Object resolvedValue = setupAlert(alert, key, value);

        testData.put(key, resolvedValue);
        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);

        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.pass!"));
        assertThat(test.runTest(progress), is(true));
    }

    @ParameterizedTest
    @MethodSource("shouldReturnValuesForMatching")
    void shouldFailOnPresentAlertWithPassIfAbsentAndIfSpecifiedValuesMatch(
            String key, String value) {
        // Given
        String action = "passIfAbsent";
        testData.put(AutomationAlertTest.PARAM_ACTION, action);

        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        Object resolvedValue = setupAlert(alert, key, value);

        testData.put(key, resolvedValue);
        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);

        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(test.runTest(progress), is(false));
    }

    private Object setupAlert(Alert alert, String key, String value) {
        Object resolvedValue = value;
        switch (key) {
            case AutomationAlertTest.PARAM_ALERT_NAME:
                alert.setName(value);
                break;
            case AutomationAlertTest.PARAM_URL:
                alert.setUri(value);
                break;
            case AutomationAlertTest.PARAM_METHOD:
                HttpMessage msg = new HttpMessage();
                msg.getRequestHeader().setMethod("GET");
                alert.setMessage(msg);
                break;
            case AutomationAlertTest.PARAM_ATTACK:
                alert.setAttack(value);
                break;
            case AutomationAlertTest.PARAM_PARAM:
                alert.setParam(value);
                break;
            case AutomationAlertTest.PARAM_EVIDENCE:
                alert.setEvidence(value);
                break;
            case AutomationAlertTest.PARAM_CONFIDENCE:
                resolvedValue = Alert.MSG_CONFIDENCE[Integer.parseInt(value)];
                alert.setConfidence(Integer.parseInt(value));
                break;
            case AutomationAlertTest.PARAM_RISK:
                resolvedValue = Alert.MSG_RISK[Integer.parseInt(value)];
                alert.setRisk(Integer.parseInt(value));
                break;
            case AutomationAlertTest.PARAM_OTHER_INFO:
                alert.setOtherInfo(value);
                break;
            default:
                break;
        }
        return resolvedValue;
    }

    @ParameterizedTest
    @MethodSource("shouldReturnValuesForMatching")
    void shouldPassOnAbsentAlertWithPassIfAbsentAndIfSpecifiedValuesDontMatch(
            String key, String value) {
        // Given
        String action = "passIfAbsent";
        testData.put(AutomationAlertTest.PARAM_ACTION, action);

        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();

        Object resolvedValue = value;

        switch (key) {
            case AutomationAlertTest.PARAM_CONFIDENCE:
                resolvedValue = Alert.MSG_CONFIDENCE[Integer.parseInt(value)];
                break;
            case AutomationAlertTest.PARAM_RISK:
                resolvedValue = Alert.MSG_RISK[Integer.parseInt(value)];
                break;
            default:
                break;
        }

        testData.put(key, resolvedValue);
        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);

        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.pass!"));
        assertThat(test.runTest(progress), is(true));
    }

    @ParameterizedTest
    @MethodSource("shouldReturnValuesForMatching")
    void shouldFailOnAbsentAlertWithPassIfPresentAndIfSpecifiedValuesDontMatch(
            String key, String value) {
        // Given
        String action = "passIfPresent";
        testData.put(AutomationAlertTest.PARAM_ACTION, action);

        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        Object resolvedValue = value;

        switch (key) {
            case AutomationAlertTest.PARAM_CONFIDENCE:
                resolvedValue = Alert.MSG_CONFIDENCE[Integer.parseInt(value)];
                break;
            case AutomationAlertTest.PARAM_RISK:
                resolvedValue = Alert.MSG_RISK[Integer.parseInt(value)];
                break;
            default:
                break;
        }

        testData.put(key, resolvedValue);
        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);

        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(test.runTest(progress), is(false));
    }

    @Test
    void shouldLogWarningsIfSpecifiedWarnOnFail() {
        // Given
        String action = "passIfPresent";
        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        testData.put(AutomationAlertTest.PARAM_ACTION, action);
        testData.put(AutomationAlertTest.PARAM_ON_FAIL, "warn");
        testData.put(AutomationAlertTest.PARAM_ALERT_NAME, "exampleAlertName");

        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);
        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getWarnings().size(), is(1));
        assertThat(progress.getWarnings().get(0), is("!automation.tests.fail!"));
        assertThat(test.runTest(progress), is(false));
    }

    @Test
    void shouldLogErrorsIfSpecifiedErrorOnFail() {
        // Given
        String action = "passIfPresent";
        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        testData.put(AutomationAlertTest.PARAM_ACTION, action);
        testData.put(AutomationAlertTest.PARAM_ON_FAIL, "error");
        testData.put(AutomationAlertTest.PARAM_ALERT_NAME, "exampleAlertName");

        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);
        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.tests.fail!"));
        assertThat(test.runTest(progress), is(false));
    }

    @Test
    void shouldLogInfoIfSpecifiedInfoOnFail() {
        // Given
        String action = "passIfPresent";
        Map<Integer, Alert> alertDataMap = new HashMap<>();
        AutomationProgress progress = new AutomationProgress();
        testData.put(AutomationAlertTest.PARAM_ACTION, action);
        testData.put(AutomationAlertTest.PARAM_ON_FAIL, "info");
        testData.put(AutomationAlertTest.PARAM_ALERT_NAME, "exampleAlertName");

        AutomationAlertTest test = new AutomationAlertTest(testData, new ActiveScanJob(), progress);
        alertDataMap.put(alert.getAlertId(), alert);
        given(data.getAllAlertData()).willReturn(alertDataMap.values());
        progress.addJobResultData(data);

        // When
        test.logToProgress(progress);

        // Then
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.getInfos().size(), is(6));
        assertThat(progress.getInfos().get(5), is("!automation.tests.fail!"));
    }
}
