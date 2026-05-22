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
package org.zaproxy.zap.extension.scripts.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Transaction;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptsRun;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptsRunOutput;
import org.zaproxy.zap.extension.scripts.internal.db.TableJdo;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ExtensionScriptAutomation}. */
class ExtensionScriptAutomationUnitTest extends TestUtils {

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionScriptsUI());
    }

    @Test
    void shouldPersistHttpSenderScriptErrorDuringAutomationPlan() throws Exception {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            Transaction tx = mock(Transaction.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.currentTransaction()).willReturn(tx);
            given(tx.isActive()).willReturn(false);

            ScriptEventListener handler = newScriptErrorHandler();
            AutomationPlan plan = mock(AutomationPlan.class);
            AutomationProgress progress = new AutomationProgress();
            when(plan.getProgress()).thenReturn(progress);
            addRunningPlan(handler, plan);

            ScriptWrapper script = mock(ScriptWrapper.class);
            when(script.getName()).thenReturn("httpsender-script");
            when(script.getTypeName()).thenReturn(ExtensionScript.TYPE_HTTP_SENDER);
            when(script.getLastErrorDetails()).thenReturn("send failed");
            when(script.getLastException()).thenReturn(new RuntimeException("persist me"));

            // When
            handler.scriptError(script);

            // Then
            assertThat(progress.getErrors(), hasSize(1));
            @SuppressWarnings("rawtypes")
            ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
            verify(pm, times(1)).makePersistent(captor.capture());
            ScriptsRun run =
                    captor.getAllValues().stream()
                            .filter(ScriptsRun.class::isInstance)
                            .map(ScriptsRun.class::cast)
                            .findFirst()
                            .orElseThrow();
            assertThat(run.getOutcome(), is(equalTo(ScriptRunRecorder.OUTCOME_FAILED)));
            assertThat(run.getScripts().get(0).getScriptName(), is(equalTo("httpsender-script")));
            ScriptsRunOutput output = run.getScripts().get(0).getSteps().get(0).getOutputs().get(0);
            assertThat(output.getKind(), is(equalTo(ScriptRunRecorder.OUTPUT_KIND_ERROR)));
            assertThat(output.getMessage(), is(equalTo("persist me")));
        }
    }

    @Test
    void shouldNotPersistStandaloneScriptErrorFromAutomationHandler() throws Exception {
        // Given
        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            ScriptEventListener handler = newScriptErrorHandler();
            ScriptWrapper script = mock(ScriptWrapper.class);
            when(script.getTypeName()).thenReturn(ExtensionScript.TYPE_STANDALONE);

            // When
            handler.scriptError(script);

            // Then
            tableJdo.verifyNoInteractions();
        }
    }

    private static ScriptEventListener newScriptErrorHandler() throws Exception {
        Class<?> handlerClass =
                Class.forName(
                        "org.zaproxy.zap.extension.scripts.automation.ExtensionScriptAutomation$ScriptErrorHandler");
        Constructor<?> constructor =
                handlerClass.getDeclaredConstructor(ExtensionScriptAutomation.class);
        constructor.setAccessible(true);
        return (ScriptEventListener) constructor.newInstance(new ExtensionScriptAutomation());
    }

    @SuppressWarnings("unchecked")
    private static void addRunningPlan(ScriptEventListener handler, AutomationPlan plan)
            throws Exception {
        Field runningPlans = handler.getClass().getDeclaredField("runningPlans");
        runningPlans.setAccessible(true);
        ((List<AutomationPlan>) runningPlans.get(handler)).add(plan);
    }
}
