/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.testutils.TestUtils;

class ExitStatusJobUnitTest extends TestUtils {

    @BeforeAll
    static void setUp() {
        mockMessages(new ExtensionAutomation());
    }

    @Test
    void shouldNotFailIfNoConfigs() {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldReturnDefaultInfo() {
        // Given / When
        ExitStatusJob job = new ExitStatusJob();
        job.getParameters().setErrorLevel("High");
        job.getParameters().setWarnLevel("Medium");

        // Then
        assertThat(job.getName(), is(equalTo("exitStatus")));
        assertThat(job.getSummary(), is(equalTo("Error: High, Warn: Medium")));
        assertThat(job.getOrder(), is(equalTo(Order.RUN_LAST)));
        assertThat(job.getParamMethodName(), is(nullValue()));
        assertThat(job.getParamMethodObject(), is(nullValue()));
    }

    @Test
    void shouldVerifyParameters() {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        String yamlStr =
                "parameters:\n"
                        + "  errorLevel: high\n"
                        + "  warnLevel: LOW\n"
                        + "  okExitValue: 1\n"
                        + "  warnExitValue: 2\n"
                        + "  errorExitValue: 3";
        Object data = new Yaml().load(yamlStr);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getParameters().getErrorLevel(), is(equalTo("high")));
        assertThat(job.getParameters().getWarnLevel(), is(equalTo("LOW")));
        assertThat(job.getParameters().getOkExitValue(), is(equalTo(1)));
        assertThat(job.getParameters().getWarnExitValue(), is(equalTo(2)));
        assertThat(job.getParameters().getErrorExitValue(), is(equalTo(3)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"informational", "LOW", "Medium", "HiGH", "   "})
    void shouldNotWarnOnValidErrorLevel(String badrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setErrorLevel(badrisk);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Invalid", "Info", "None", "-"})
    void shouldWarnOnInvalidErrorLevel(String badrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setErrorLevel(badrisk);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("Invalid risk for job exitStatus : " + badrisk)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"informational", "LOW", "Medium", "HiGH", "   "})
    void shouldNotWarnOnValidWarnLevel(String badrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setWarnLevel(badrisk);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Invalid", "Info", "None", "-"})
    void shouldWarnOnInvalidWarnLevel(String badrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setWarnLevel(badrisk);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("Invalid risk for job exitStatus : " + badrisk)));
    }

    @ParameterizedTest
    @CsvSource({
        "high,Medium",
        "HIGH, Medium",
        "High,Informational",
        "medium,LOW",
        "medium,INFORMATIOnaL",
        "low,informational"
    })
    void shouldWarnOnWarnGreaterThanError(String warnrisk, String errorrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setWarnLevel(warnrisk);
        job.getParameters().setErrorLevel(errorrisk);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(
                        equalTo(
                                "Error level: "
                                        + errorrisk
                                        + " is lower than warn level: "
                                        + warnrisk)));
    }

    @ParameterizedTest
    @CsvSource({
        "high,Medium",
        "HIGH, Medium",
        "High,Informational",
        "medium,LOW",
        "medium,INFORMATIOnaL",
        "low,informational"
    })
    void shouldNotWarnOnAlertsLessThanMinimumLevel(String warnrisk, String alertrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk));

        // When
        job.getParameters().setWarnLevel(warnrisk);
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({
        "high,Medium",
        "HIGH, Medium",
        "High,Informational",
        "medium,LOW",
        "medium,INFORMATIOnaL",
        "low,informational"
    })
    void shouldNotErrorOnAlertsLessThanMinimumLevel(String errorrisk, String alertrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk));

        // When
        job.getParameters().setErrorLevel(errorrisk);
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @CsvSource({
        "HIGH,high",
        "high,Medium",
        "HIGH, Medium",
        "High,Informational",
        "medium,medium",
        "medium,LOW",
        "medium,INFORMATIOnaL",
        "low,LOW",
        "low,informational",
        "informational,informational"
    })
    void shouldWarnOnAlertsWithMinimumLevel(String alertrisk, String warnrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk));

        // When
        job.getParameters().setWarnLevel(warnrisk);
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("An alert has been raised with a risk of at least: " + warnrisk)));
    }

    @ParameterizedTest
    @CsvSource({
        "HIGH,high",
        "high,Medium",
        "HIGH, Medium",
        "High,Informational",
        "medium,medium",
        "medium,LOW",
        "medium,INFORMATIOnaL",
        "low,LOW",
        "low,informational",
        "informational,informational"
    })
    void shouldErrorOnAlertsWithMinimumLevel(String alertrisk, String errorrisk) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk));

        // When
        job.getParameters().setErrorLevel(errorrisk);
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("An alert has been raised with a risk of at least: " + errorrisk)));
    }

    @ParameterizedTest
    @CsvSource({"HIGH,4", "medium,3", "low,2"})
    void shouldSetExitCode(String alertrisk, String exitcode) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk));

        // When
        job.getParameters().setOkExitValue(2);
        job.getParameters().setWarnExitValue(3);
        job.getParameters().setErrorExitValue(4);
        job.getParameters().setErrorLevel("high");
        job.getParameters().setWarnLevel("medium");
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(ExtensionAutomation.getExitOverride(), is(equalTo(Integer.parseInt(exitcode))));
    }

    @ParameterizedTest
    @CsvSource({
        "HIGH,MEDIUM,4",
        "medium,medium,3",
        "low,medium,2",
        "High,False Positive,0",
        "Medium,False Positive,0",
        "Low,False Positive,0"
    })
    void shouldSetExitCodeExcludingFalsePositive(
            String alertrisk, String confidence, String exitcode) {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData(alertrisk, confidence, true, false));

        // When
        job.getParameters().setOkExitValue(Integer.parseInt(exitcode) > 0 ? 2 : 0);
        job.getParameters().setWarnExitValue(3);
        job.getParameters().setErrorExitValue(4);
        job.getParameters().setErrorLevel("high");
        job.getParameters().setWarnLevel("medium");
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);

        // Then
        assertThat(ExtensionAutomation.getExitOverride(), is(equalTo(Integer.parseInt(exitcode))));
    }

    @Test
    void shouldSetExitCodeBasedOnAlerts() {
        // Given
        ExitStatusJob job = new ExitStatusJob();
        AutomationProgress progress = new AutomationProgress();
        progress.addJobResultData(getTestData("medium", "false positive", true, true));
        // When
        job.getParameters().setOkExitValue(1);
        job.getParameters().setWarnExitValue(2);
        job.getParameters().setErrorExitValue(3);
        job.getParameters().setErrorLevel("high");
        job.getParameters().setWarnLevel("medium");
        job.verifyParameters(progress);
        job.runJob(new AutomationEnvironment(progress), progress);
        // Then
        assertThat(ExtensionAutomation.getExitOverride(), is(equalTo(3)));
    }

    private static JobResultData getTestData(String alertLevel) {
        return getTestData(alertLevel, "Medium", true, false);
    }

    private static JobResultData getTestData(
            String alertLevel,
            String confidence,
            boolean includeBaseAlert,
            boolean includeExtraAlerts) {
        Alert alert =
                new Alert(
                        -1,
                        JobUtils.parseAlertRisk(alertLevel),
                        JobUtils.parseAlertConfidence(confidence),
                        "test");

        return new JobResultData("test") {

            @Override
            public String getKey() {
                return "test";
            }

            @Override
            public Collection<Alert> getAllAlertData() {
                List<Alert> alertList = new ArrayList<>();
                if (includeBaseAlert) {
                    alertList.add(alert);
                }
                if (includeExtraAlerts) {
                    alertList.add(new Alert(-1, 3, 3, "test"));
                }
                return alertList;
            }
        };
    }
}
