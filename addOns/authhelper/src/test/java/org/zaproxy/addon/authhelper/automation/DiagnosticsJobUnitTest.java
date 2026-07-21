/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.LinkedHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.MockedConstruction;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;

class DiagnosticsJobUnitTest extends TestUtils {

    private AutomationEnvironment env;
    private AutomationPlan plan;
    private AutomationProgress progress;
    private Context context;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAuthhelper());
        plan = mock(AutomationPlan.class);
        env = mock(AutomationEnvironment.class);
        context = mock(Context.class);
        lenient().when(context.getName()).thenReturn("Default Context");
        lenient().when(env.getDefaultContext()).thenReturn(context);
        lenient().when(env.getPlan()).thenReturn(plan);
        progress = new AutomationProgress();
    }

    @AfterEach
    void tearDown() {
        DiagnosticsJob cleanup = new DiagnosticsJob();
        cleanup.setPlan(plan);
        cleanup.planFinished();
    }

    private static DiagnosticsJob jobFor(AutomationPlan plan) {
        DiagnosticsJob job = new DiagnosticsJob();
        job.setPlan(plan);
        return job;
    }

    @Test
    void shouldApplyEnabledParamAndExposeTypeTemplates() {
        // Given
        DiagnosticsJob job = new DiagnosticsJob();
        Object data = new Yaml().load("parameters:\n  enabled: true");
        job.setJobData((LinkedHashMap<?, ?>) data);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(job.getType(), is(equalTo("diagnostics")));
        assertThat(job.getTemplateDataMin(), containsString("type: diagnostics"));
        assertThat(job.getTemplateDataMax(), containsString("enabled:"));
        assertThat(job.getParameters().isEnabled(), is(equalTo(true)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldStartRecordingWhenEnabledTrueAndOff() {
        try (MockedConstruction<AuthenticationDiagnostics> diags =
                mockConstruction(AuthenticationDiagnostics.class)) {
            // Given
            DiagnosticsJob job = jobFor(plan);
            job.getParameters().setEnabled(true);

            // When
            job.runJob(env, progress);

            // Then
            assertThat(diags.constructed(), hasSize(1));
            assertThat(progress.hasErrors(), is(equalTo(false)));
            assertThat(
                    progress.getInfos().toString(),
                    containsString("started diagnostics recording"));
        }
    }

    @Test
    void shouldWarnWhenEnabledTrueAndAlreadyOn() {
        try (MockedConstruction<AuthenticationDiagnostics> diags =
                mockConstruction(AuthenticationDiagnostics.class)) {
            // Given
            DiagnosticsJob job = jobFor(plan);
            job.getParameters().setEnabled(true);
            job.runJob(env, progress);
            progress = new AutomationProgress();

            // When
            job.runJob(env, progress);

            // Then
            assertThat(diags.constructed(), hasSize(1));
            verify(diags.constructed().get(0), never()).close();
            assertThat(progress.hasWarnings(), is(equalTo(true)));
            assertThat(
                    progress.getWarnings().toString(),
                    containsString("diagnostics recording is already enabled"));
        }
    }

    @Test
    void shouldStopRecordingWhenEnabledFalseAndOn() {
        try (MockedConstruction<AuthenticationDiagnostics> diags =
                mockConstruction(AuthenticationDiagnostics.class)) {
            // Given
            DiagnosticsJob start = jobFor(plan);
            start.getParameters().setEnabled(true);
            start.runJob(env, progress);
            DiagnosticsJob stop = jobFor(plan);
            stop.getParameters().setEnabled(false);
            progress = new AutomationProgress();

            // When
            stop.runJob(env, progress);

            // Then
            AuthenticationDiagnostics recording = diags.constructed().get(0);
            InOrder inOrder = inOrder(recording);
            inOrder.verify(recording).recordStep("Diagnostics Recording");
            inOrder.verify(recording).close();
            assertThat(
                    progress.getInfos().toString(),
                    containsString("stopped diagnostics recording"));
        }
    }

    @Test
    void shouldWarnWhenEnabledFalseAndAlreadyOff() {
        // Given
        DiagnosticsJob job = jobFor(plan);
        job.getParameters().setEnabled(false);

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings().toString(),
                containsString("diagnostics recording is not enabled"));
    }

    @Test
    void shouldStopOnPlanFinished() {
        try (MockedConstruction<AuthenticationDiagnostics> diags =
                mockConstruction(AuthenticationDiagnostics.class)) {
            // Given
            DiagnosticsJob job = jobFor(plan);
            job.getParameters().setEnabled(true);
            job.runJob(env, progress);

            // When
            job.planFinished();

            // Then
            AuthenticationDiagnostics recording = diags.constructed().get(0);
            InOrder inOrder = inOrder(recording);
            inOrder.verify(recording).recordStep("Diagnostics Recording");
            inOrder.verify(recording).close();
        }
    }

    @Test
    void shouldKeepRecordingsIndependentPerPlan() {
        try (MockedConstruction<AuthenticationDiagnostics> diags =
                mockConstruction(AuthenticationDiagnostics.class)) {
            // Given
            AutomationPlan otherPlan = mock(AutomationPlan.class);
            AutomationEnvironment otherEnv = mock(AutomationEnvironment.class);
            lenient().when(otherEnv.getDefaultContext()).thenReturn(context);
            lenient().when(otherEnv.getPlan()).thenReturn(otherPlan);

            DiagnosticsJob job1 = jobFor(plan);
            job1.getParameters().setEnabled(true);
            job1.runJob(env, progress);

            DiagnosticsJob job2 = jobFor(otherPlan);
            job2.getParameters().setEnabled(true);
            job2.runJob(otherEnv, progress);

            try {
                // When
                job1.planFinished();

                // Then
                assertThat(diags.constructed(), hasSize(2));
                verify(diags.constructed().get(0)).close();
                verify(diags.constructed().get(1), never()).close();
            } finally {
                job2.planFinished();
            }
            verify(diags.constructed().get(1)).close();
        }
    }
}
