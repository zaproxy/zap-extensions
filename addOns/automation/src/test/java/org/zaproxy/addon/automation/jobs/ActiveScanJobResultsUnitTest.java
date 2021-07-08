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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.AbstractPlugin;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.db.Database;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordAlert;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.ascan.ActiveScan;

class ActiveScanJobResultsUnitTest {
    @Test
    void shouldReturnJobData() {
        // Given
        ActiveScan activeScan = mock(ActiveScan.class);
        HostProcess hp = mock(HostProcess.class);
        List<HostProcess> listHp = new ArrayList<>();
        listHp.add(hp);
        given(activeScan.getHostProcesses()).willReturn(listHp);
        List<Plugin> listPlugin = new ArrayList<>();
        listPlugin.add(new TestPlugin("test1", 1));
        listPlugin.add(new TestPlugin("test2", 2));
        given(hp.getCompleted()).willReturn(listPlugin);

        // When
        ActiveScanJobResultData data = new ActiveScanJobResultData("test", activeScan);

        // Then
        assertThat(data, is(notNullValue()));
        assertThat(data.getKey(), is(equalTo("activeScanData")));
        assertThat(data.getAllRuleData().size(), is(equalTo(2)));
        assertThat(data.getRuleData(1), is(notNullValue()));
        assertThat(data.getRuleData(1).getId(), is(equalTo(1)));
        assertThat(data.getRuleData(1).getName(), is(equalTo("test1")));
        assertThat(data.getRuleData(1).getThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(data.getRuleData(1).getStrength(), is(equalTo(AttackStrength.MEDIUM)));
        assertThat(data.getRuleData(1).getTimeTakenMs(), is(equalTo(10L)));
        assertThat(data.getRuleData(2), is(notNullValue()));
        assertThat(data.getRuleData(2).getId(), is(equalTo(2)));
        assertThat(data.getRuleData(2).getName(), is(equalTo("test2")));
        assertThat(data.getRuleData(2).getThreshold(), is(equalTo(AlertThreshold.MEDIUM)));
        assertThat(data.getRuleData(1).getStrength(), is(equalTo(AttackStrength.MEDIUM)));
        assertThat(data.getRuleData(2).getTimeTakenMs(), is(equalTo(20L)));
    }

    @Test
    void shouldReturnAlertData() throws DatabaseException {
        // Given
        ActiveScan activeScan = mock(ActiveScan.class);
        List<Integer> alertIds = Arrays.asList(1, 2);
        given(activeScan.getAlertsIds()).willReturn(alertIds);
        RecordAlert recordOne =
                new RecordAlert(
                        1,
                        1,
                        100,
                        "AlertOne",
                        1,
                        1,
                        "DescOne",
                        "UriOne",
                        "ParamOne",
                        "AttackOne",
                        "OtherInfoOne",
                        "SolnOne",
                        "RefOne",
                        "EvidenceOne",
                        10,
                        20,
                        30,
                        40,
                        1,
                        "100AlertOne");
        RecordAlert recordTwo =
                new RecordAlert(
                        2,
                        1,
                        200,
                        "AlertTwo",
                        2,
                        2,
                        "DescTwo",
                        "UriTwo",
                        "ParamTwo",
                        "AttackTwo",
                        "OtherInfoTwo",
                        "SolnTwo",
                        "RefTwo",
                        "EvidenceTwo",
                        100,
                        200,
                        300,
                        400,
                        2,
                        "200AlertTwo");
        TableAlert table = mock(TableAlert.class);
        given(table.read(1)).willReturn(recordOne);
        given(table.read(2)).willReturn(recordTwo);
        Database db = mock(Database.class);
        given(db.getTableAlert()).willReturn(table);
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        given(model.getDb()).willReturn(db);

        // When
        ActiveScanJobResultData data = new ActiveScanJobResultData("test", activeScan);

        // Then
        assertThat(data, is(notNullValue()));
        assertThat(data.getKey(), is(equalTo("activeScanData")));
        assertThat(data.getAllAlertData().size(), is(equalTo(2)));

        assertThat(data.getAlertData(1), is(notNullValue()));
        assertThat(data.getAlertData(1).getAlertId(), is(equalTo(1)));
        assertThat(data.getAlertData(1).getPluginId(), is(equalTo(100)));
        assertThat(data.getAlertData(1).getName(), is(equalTo("AlertOne")));
        assertThat(data.getAlertData(1).getRisk(), is(equalTo(1)));
        assertThat(data.getAlertData(1).getConfidence(), is(equalTo(1)));
        assertThat(data.getAlertData(1).getDescription(), is(equalTo("DescOne")));
        assertThat(data.getAlertData(1).getUri(), is(equalTo("UriOne")));
        assertThat(data.getAlertData(1).getParam(), is(equalTo("ParamOne")));
        assertThat(data.getAlertData(1).getAttack(), is(equalTo("AttackOne")));
        assertThat(data.getAlertData(1).getOtherInfo(), is(equalTo("OtherInfoOne")));
        assertThat(data.getAlertData(1).getSolution(), is(equalTo("SolnOne")));
        assertThat(data.getAlertData(1).getReference(), is(equalTo("RefOne")));
        assertThat(data.getAlertData(1).getEvidence(), is(equalTo("EvidenceOne")));
        assertThat(data.getAlertData(1).getCweId(), is(equalTo(10)));
        assertThat(data.getAlertData(1).getWascId(), is(equalTo(20)));
        assertThat(data.getAlertData(1).getAlertRef(), is(equalTo("100AlertOne")));

        assertThat(data.getAlertData(2), is(notNullValue()));
        assertThat(data.getAlertData(2).getAlertId(), is(equalTo(2)));
        assertThat(data.getAlertData(2).getPluginId(), is(equalTo(200)));
        assertThat(data.getAlertData(2).getName(), is(equalTo("AlertTwo")));
        assertThat(data.getAlertData(2).getRisk(), is(equalTo(2)));
        assertThat(data.getAlertData(2).getConfidence(), is(equalTo(2)));
        assertThat(data.getAlertData(2).getDescription(), is(equalTo("DescTwo")));
        assertThat(data.getAlertData(2).getUri(), is(equalTo("UriTwo")));
        assertThat(data.getAlertData(2).getParam(), is(equalTo("ParamTwo")));
        assertThat(data.getAlertData(2).getAttack(), is(equalTo("AttackTwo")));
        assertThat(data.getAlertData(2).getOtherInfo(), is(equalTo("OtherInfoTwo")));
        assertThat(data.getAlertData(2).getSolution(), is(equalTo("SolnTwo")));
        assertThat(data.getAlertData(2).getReference(), is(equalTo("RefTwo")));
        assertThat(data.getAlertData(2).getEvidence(), is(equalTo("EvidenceTwo")));
        assertThat(data.getAlertData(2).getCweId(), is(equalTo(100)));
        assertThat(data.getAlertData(2).getWascId(), is(equalTo(200)));
        assertThat(data.getAlertData(2).getAlertRef(), is(equalTo("200AlertTwo")));
    }

    private class TestPlugin extends AbstractPlugin {

        private String name;
        private int pluginId;
        private Date date;

        public TestPlugin(String name, int pluginId) {
            this.name = name;
            this.pluginId = pluginId;
            this.date = new Date();
        }

        @Override
        public int getId() {
            return this.pluginId;
        }

        @Override
        public String getName() {
            return this.name;
        }

        @Override
        public Date getTimeStarted() {
            return new Date(this.date.getTime() + (pluginId * 10));
        }

        @Override
        public Date getTimeFinished() {
            return this.date;
        }

        @Override
        public String getDescription() {
            return null;
        }

        @Override
        public void scan() {}

        @Override
        public int getCategory() {
            return 0;
        }

        @Override
        public String getSolution() {
            return null;
        }

        @Override
        public String getReference() {
            return null;
        }

        @Override
        public void notifyPluginCompleted(HostProcess parent) {}
    }
}
