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
package org.zaproxy.zap.extension.scripts.report;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;

import java.util.List;
import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.jdo.Query;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunTestFixtures;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptsRun;
import org.zaproxy.zap.extension.scripts.internal.db.TableJdo;

/** Unit tests for {@link ExtensionScriptsReport}. */
class ExtensionScriptsReportUnitTest {

    @Test
    void shouldFilterRunsWithErrorsAtQueryWhenOutputSectionDisabled() {
        // Given
        ScriptsRun failedRun = ScriptRunTestFixtures.defaultFailedChainRunWithErrorStep();

        try (MockedStatic<TableJdo> tableJdo = mockStatic(TableJdo.class)) {
            PersistenceManagerFactory pmf = mock(PersistenceManagerFactory.class);
            PersistenceManager pm = mock(PersistenceManager.class);
            @SuppressWarnings("unchecked")
            Query<ScriptsRun> query = mock(Query.class);
            tableJdo.when(TableJdo::getPmf).thenReturn(pmf);
            given(pmf.getPersistenceManager()).willReturn(pm);
            given(pm.newQuery(ScriptsRun.class)).willReturn(query);
            given(query.executeList()).willReturn(List.of(failedRun));

            ReportData reportData = new ReportData("test");
            reportData.setSections(List.of("scriptdiagnostics"));
            reportData.setAlertTreeRootNode(new AlertNode(0, "Test"));

            // When
            new ExtensionScriptsReport.ScriptsReportDataHandler().handle(reportData);

            // Then
            ScriptRunReportData.Diagnostics diagnostics =
                    (ScriptRunReportData.Diagnostics)
                            reportData
                                    .getReportObjects()
                                    .get(ExtensionScriptsReport.SCRIPT_DIAGNOSTICS);
            assertThat(diagnostics.runs(), hasSize(1));
            assertThat(
                    diagnostics.runs().get(0).outcome(),
                    is(equalTo(ScriptRunRecorder.OUTCOME_FAILED)));

            verify(query)
                    .setFilter(
                            "this.scripts.contains(s) && s.steps.contains(st)"
                                    + " && st.outputs.contains(o) && o.kind == :kind");
        }
    }
}
