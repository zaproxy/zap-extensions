/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ascan.ActiveScan;

/** Unit test for {@link ActiveScanJobResultData}. */
class ActiveScanJobResultDataUnitTest {

    private static final String JOB_NAME = "Job Name";

    private List<HostProcess> hostProcesses;
    private List<Integer> alertIds;
    private TableAlert tableAlert;

    private ActiveScan activeScan;

    @BeforeEach
    void setUp() {
        activeScan = mock(ActiveScan.class);
        hostProcesses = new ArrayList<>();
        given(activeScan.getHostProcesses()).willReturn(hostProcesses);
        alertIds = new ArrayList<>();
        given(activeScan.getAlertsIds()).willReturn(alertIds);

        Database db = mock(Database.class);
        tableAlert = mock(TableAlert.class);
        given(db.getTableAlert()).willReturn(tableAlert);

        Model model = mock(Model.class);
        given(model.getDb()).willReturn(db);
        Model.setSingletonForTesting(model);
    }

    @Test
    void shouldReadAllAlerts() throws Exception {
        // Given
        mockPersistedAlert(1);
        mockPersistedAlert(2);
        // When
        ActiveScanJobResultData data = new ActiveScanJobResultData(JOB_NAME, activeScan);
        // Then
        assertThat(data.getAllAlertData(), hasSize(2));
    }

    @Test
    void shouldNotFailIfAlertNoLongerExists() throws Exception {
        // Given
        mockPersistedAlert(1);
        mockPersistedAlert(2);
        given(tableAlert.read(1)).willReturn(null);
        // When
        ActiveScanJobResultData data = new ActiveScanJobResultData(JOB_NAME, activeScan);
        // Then
        assertThat(data.getAllAlertData(), hasSize(1));
    }

    private void mockPersistedAlert(int id) throws Exception {
        given(tableAlert.read(id)).willReturn(mock(RecordAlert.class));
        alertIds.add(id);
    }
}
