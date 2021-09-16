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
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class RetestPlanGeneratorUnitTest extends TestUtils {

    private static AutomationPlan retestPlan;

    @BeforeAll
    static void init() {
        Constant.messages = mock(I18N.class);
        mockMessages(new ExtensionAutomation());
        List<AlertData> alertData = new ArrayList<>();
        HttpMessage msgOne = new HttpMessage();
        Alert alertOne = new Alert(100);
        alertOne.setSource(Alert.Source.ACTIVE);
        AlertData alertOneData = new AlertData();
        alertOneData.setScanRuleId(100);
        alertOneData.setAlertName("Test Alert One");
        alertOneData.setUrl("https://www.exampleone.com");
        alertOneData.setMethod("GET");
        alertOneData.setAttack("Test Attack One");
        alertOneData.setParam("Test Param One");
        alertOneData.setEvidence("Test Evidence One");
        alertOneData.setConfidence("Test Confidence One");
        alertOneData.setRisk("Test Risk One");
        alertOneData.setOtherInfo("Test Other Info One");
        alertOneData.setMsg(msgOne);
        alertOneData.setAlert(alertOne);

        HttpMessage msgTwo = new HttpMessage();
        msgTwo.setRequestBody(new HttpRequestBody("Test Body"));
        Alert alertTwo = new Alert(200);
        alertTwo.setSource(Alert.Source.PASSIVE);
        AlertData alertTwoData = new AlertData();
        alertTwoData.setScanRuleId(200);
        alertTwoData.setAlertName("Test Alert Two");
        alertTwoData.setUrl("https://www.exampletwo.com");
        alertTwoData.setMethod("POST");
        alertTwoData.setAttack("Test Attack Two");
        alertTwoData.setParam("Test Param Two");
        alertTwoData.setEvidence("Test Evidence Two");
        alertTwoData.setConfidence("Test Confidence Two");
        alertTwoData.setRisk("Test Risk Two");
        alertTwoData.setOtherInfo("Test Other Info Two");
        alertTwoData.setMsg(msgTwo);
        alertTwoData.setAlert(alertTwo);

        alertData.add(alertOneData);
        alertData.add(alertTwoData);

        retestPlan = new RetestPlanGenerator(alertData).getPlan();
    }

    @BeforeEach
    void setUp() throws Exception {
        mockMessages(new ExtensionAutomation());
        super.setUpZap();
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);
    }

    @Test
    void shouldGenerateEnvironment() {
        // Given / When
        AutomationEnvironment env = retestPlan.getEnv();

        // Then
        ContextWrapper.Data context = env.getData().getContexts().get(0);
        assertThat(context.getName(), is(equalTo("Retest Plan")));
        assertThat(context.getUrls().size(), is(equalTo(2)));
        assertThat(context.getUrls().get(0), is(equalTo("https://www.exampleone.com")));
        assertThat(context.getUrls().get(1), is(equalTo("https://www.exampletwo.com")));
    }

    @Test
    void shouldGenerateAllJobs() {
        // Given / When
        List<AutomationJob> jobs = retestPlan.getJobs();

        // Then
        assertThat(jobs.size(), is(equalTo(4)));
        assertThat(jobs.get(0), is(instanceOf(PassiveScanConfigJob.class)));
        assertThat(jobs.get(1), is(instanceOf(RequestorJob.class)));
        assertThat(jobs.get(2), is(instanceOf(ActiveScanJob.class)));
        assertThat(jobs.get(3), is(instanceOf(PassiveScanWaitJob.class)));
    }

    @Test
    void shouldGenerateRequestorJob() {
        // Given / When
        RequestorJob job = (RequestorJob) retestPlan.getJob(1);
        List<RequestorJob.Request> requests = job.getData().getRequests();

        // Then
        assertThat(requests.size(), is(equalTo(2)));
        assertThat(requests.get(0).getUrl(), is(equalTo("https://www.exampleone.com")));
        assertThat(requests.get(0).getMethod(), is(equalTo("GET")));
        assertThat(requests.get(0).getName(), is(equalTo("Test Alert One")));
        assertThat(requests.get(0).getData(), is(equalTo("")));
        assertThat(requests.get(0).getResponseCode(), is(equalTo(null)));
        assertThat(requests.get(1).getUrl(), is(equalTo("https://www.exampletwo.com")));
        assertThat(requests.get(1).getMethod(), is(equalTo("POST")));
        assertThat(requests.get(1).getName(), is(equalTo("Test Alert Two")));
        assertThat(requests.get(1).getData(), is(equalTo("Test Body")));
        assertThat(requests.get(1).getResponseCode(), is(equalTo(null)));
    }

    @Test
    void shouldGenerateActiveScanJob() {
        // Given / When
        ActiveScanJob job = (ActiveScanJob) retestPlan.getJob(2);
        ActiveScanJob.Data data = job.getData();

        // Then
        assertThat(data.getParameters().getContext(), is(equalTo("Retest Plan")));
        assertThat(data.getPolicyDefinition().getDefaultThreshold(), is(equalTo("Off")));
        assertThat(data.getPolicyDefinition().getRules().size(), is(equalTo(1)));
        assertThat(data.getPolicyDefinition().getRules().get(0).getId(), is(equalTo(100)));
        assertThat(
                data.getPolicyDefinition().getRules().get(0).getName(),
                is(equalTo("Test Alert One")));
        assertThat(
                data.getPolicyDefinition().getRules().get(0).getThreshold(), is(equalTo("Medium")));
        assertThat(
                data.getPolicyDefinition().getRules().get(0).getStrength(), is(equalTo("Medium")));
        assertThat(data.getTests().size(), is(equalTo(1)));
    }

    @Test
    void shouldGeneratePassiveScanWaitJob() {
        // Given / When
        PassiveScanWaitJob job = (PassiveScanWaitJob) retestPlan.getJob(3);
        PassiveScanWaitJob.Data data = job.getData();

        // Then
        assertThat(data.getTests().size(), is(equalTo(1)));
    }

    @Test
    void shouldGenerateTestForActiveAlert() {
        // Given / When
        AutomationAlertTest alertTest =
                (AutomationAlertTest) retestPlan.getJob(2).getTests().get(0);
        AutomationAlertTest.Data data = alertTest.getData();

        // Then
        assertThat(data.getOnFail(), is(equalTo(AbstractAutomationTest.OnFail.WARN)));
        assertThat(data.getScanRuleId(), is(equalTo(100)));
        assertThat(data.getAlertName(), is(equalTo("Test Alert One")));
        assertThat(data.getAction(), is(equalTo(AutomationAlertTest.ACTION_PASS_IF_ABSENT)));
        assertThat(data.getUrl(), is(equalTo("https://www.exampleone.com")));
        assertThat(data.getMethod(), is(equalTo("GET")));
        assertThat(data.getParam(), is(equalTo("Test Param One")));
        assertThat(data.getAttack(), is(equalTo("Test Attack One")));
        assertThat(data.getEvidence(), is(equalTo("Test Evidence One")));
        assertThat(data.getConfidence(), is(equalTo("Test Confidence One")));
        assertThat(data.getRisk(), is(equalTo("Test Risk One")));
        assertThat(data.getOtherInfo(), is(equalTo("Test Other Info One")));
    }

    @Test
    void shouldGenerateTestForPassiveAlert() {
        // Given / When
        AutomationAlertTest alertTest =
                (AutomationAlertTest) retestPlan.getJob(3).getTests().get(0);
        AutomationAlertTest.Data data = alertTest.getData();

        // Then
        assertThat(data.getOnFail(), is(equalTo(AbstractAutomationTest.OnFail.WARN)));
        assertThat(data.getScanRuleId(), is(equalTo(200)));
        assertThat(data.getAlertName(), is(equalTo("Test Alert Two")));
        assertThat(data.getAction(), is(equalTo(AutomationAlertTest.ACTION_PASS_IF_ABSENT)));
        assertThat(data.getUrl(), is(equalTo("https://www.exampletwo.com")));
        assertThat(data.getMethod(), is(equalTo("POST")));
        assertThat(data.getParam(), is(equalTo("Test Param Two")));
        assertThat(data.getAttack(), is(equalTo("Test Attack Two")));
        assertThat(data.getEvidence(), is(equalTo("Test Evidence Two")));
        assertThat(data.getConfidence(), is(equalTo("Test Confidence Two")));
        assertThat(data.getRisk(), is(equalTo("Test Risk Two")));
        assertThat(data.getOtherInfo(), is(equalTo("Test Other Info Two")));
    }
}
