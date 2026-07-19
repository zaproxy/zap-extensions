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
package org.zaproxy.addon.insights.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link InsightsJob}. */
class InsightsJobUnitTest extends TestUtils {

    private InsightsJob job;
    private ExtensionInsights extInsights;
    private AutomationEnvironment env;
    private AutomationPlan plan;
    private AutomationProgress progress;

    @BeforeAll
    static void setupMessages() {
        mockMessages(new ExtensionInsights());
    }

    @BeforeEach
    void setUp() {
        extInsights = mock(ExtensionInsights.class);
        ExtensionLoader loader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), loader);
        lenient().when(loader.getExtension(ExtensionInsights.class)).thenReturn(extInsights);

        env = mock(AutomationEnvironment.class);
        plan = mock(AutomationPlan.class);
        progress = mock(AutomationProgress.class);

        job = new InsightsJob();
        job.setEnv(env);
        job.getParameters().setExitAutoOnHigh(true);
    }

    private void wireEnvForStop() {
        given(env.getPlan()).willReturn(plan);
        given(plan.getProgress()).willReturn(progress);
    }

    @Test
    void shouldStopPlanAndRecordStoppingInsightOnHighInsight() {
        // Given
        wireEnvForStop();
        Insight ins =
                new Insight(
                        Insight.Level.HIGH,
                        Insight.Reason.EXCEEDED_HIGH,
                        "https://example.com",
                        "insight.auth.failure",
                        "desc",
                        75,
                        true);
        // When
        job.recordInsight(ins);
        // Then
        verify(extInsights).setStoppingInsight(ins);
        verify(plan).stopPlan(false);
        ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
        verify(progress).warn(msg.capture());
        assertThat(msg.getValue(), containsString("insight.auth.failure"));
        assertThat(msg.getValue(), containsString("https://example.com"));
    }

    @Test
    void shouldUseGlobalSiteLabelWhenSiteEmpty() {
        // Given
        wireEnvForStop();
        Insight ins =
                new Insight(
                        Insight.Level.HIGH,
                        Insight.Reason.EXCEEDED_HIGH,
                        "",
                        "insight.memory.usage",
                        "desc",
                        95,
                        true);
        // When
        job.recordInsight(ins);
        // Then
        ArgumentCaptor<String> msg = ArgumentCaptor.forClass(String.class);
        verify(progress).warn(msg.capture());
        assertThat(msg.getValue(), containsString("insight.memory.usage"));
        assertThat(msg.getValue(), containsString("<global>"));
    }

    @Test
    void shouldNotStopPlanWhenExitAutoOnHighDisabled() {
        // Given
        job.getParameters().setExitAutoOnHigh(false);
        Insight ins =
                new Insight(
                        Insight.Level.HIGH,
                        Insight.Reason.EXCEEDED_HIGH,
                        "site",
                        "key",
                        "desc",
                        1,
                        false);
        // When
        job.recordInsight(ins);
        // Then
        verify(extInsights, never()).setStoppingInsight(any());
        verify(plan, never()).stopPlan(false);
        verify(progress, never()).warn(any(String.class));
    }

    @Test
    void shouldNotStopPlanOnNonHighInsight() {
        // Given
        Insight ins =
                new Insight(
                        Insight.Level.MEDIUM,
                        Insight.Reason.EXCEEDED_LOW,
                        "site",
                        "key",
                        "desc",
                        1,
                        false);
        // When
        job.recordInsight(ins);
        // Then
        verify(extInsights, never()).setStoppingInsight(any());
        verify(plan, never()).stopPlan(false);
    }
}
