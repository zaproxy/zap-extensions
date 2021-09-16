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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.jobs.RequestorJob;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;

public class RetestPlanGenerator {

    List<AlertData> alertDataList;

    public RetestPlanGenerator(List<AlertData> alertDataList) {
        this.alertDataList = alertDataList;
    }

    public AutomationPlan getPlan() {
        AutomationProgress planProgress = new AutomationProgress();
        AutomationEnvironment planEnv = getEnvironment(planProgress);
        List<AutomationJob> planJobs = getAllJobs(planEnv);
        return new AutomationPlan(planEnv, planJobs, planProgress);
    }

    private AutomationEnvironment getEnvironment(AutomationProgress progress) {
        AutomationEnvironment env = new AutomationEnvironment(progress);
        AutomationEnvironment.Data data = env.getData();

        ContextWrapper.Data cwd = new ContextWrapper.Data();
        cwd.setName("Retest Plan");
        cwd.setUrls(alertDataList.stream().map(AlertData::getUrl).collect(Collectors.toList()));
        List<ContextWrapper.Data> contextList = new ArrayList<>();
        contextList.add(cwd);
        data.setContexts(contextList);

        env.addContext(cwd);
        return env;
    }

    private List<AutomationJob> getAllJobs(AutomationEnvironment env) {
        List<AutomationJob> jobs = new ArrayList<>();
        jobs.add(new PassiveScanConfigJob());
        jobs.add(getRequestorJob());
        alertDataList.stream()
                .filter(t -> t.getAlert().getSource().equals(Alert.Source.ACTIVE))
                .map(this::getActiveScanJob)
                .forEach(jobs::add);
        jobs.add(getPassiveScanWaitJob());
        jobs.forEach(t -> t.setEnv(env));
        return jobs;
    }

    private RequestorJob getRequestorJob() {
        RequestorJob reqJob = new RequestorJob();
        List<RequestorJob.Request> requests =
                alertDataList.stream()
                        .map(
                                t ->
                                        new RequestorJob.Request(
                                                t.getUrl(),
                                                t.getAlertName(),
                                                t.getMethod(),
                                                t.getMsg().getRequestBody().toString(),
                                                null))
                        .collect(Collectors.toList());
        reqJob.getData().setRequests(requests);
        return reqJob;
    }

    private ActiveScanJob getActiveScanJob(AlertData alertData) {
        ActiveScanJob activeScanJob = new ActiveScanJob();
        activeScanJob.getParameters().setContext("Retest Plan");
        activeScanJob.getData().getPolicyDefinition().setDefaultThreshold("Off");
        List<ActiveScanJob.Rule> rules = new ArrayList<>();
        rules.add(
                new ActiveScanJob.Rule(
                        alertData.getScanRuleId(), alertData.getAlertName(), "Medium", "Medium"));
        activeScanJob.getData().getPolicyDefinition().setRules(rules);
        activeScanJob.addTest(getAlertTest(alertData, activeScanJob));

        return activeScanJob;
    }

    private PassiveScanWaitJob getPassiveScanWaitJob() {
        PassiveScanWaitJob waitJob = new PassiveScanWaitJob();
        alertDataList.stream()
                .filter(t -> t.getAlert().getSource().equals(Alert.Source.PASSIVE))
                .map(t -> getAlertTest(t, waitJob))
                .forEach(waitJob::addTest);
        return waitJob;
    }

    private AutomationAlertTest getAlertTest(AlertData alertData, AutomationJob job) {
        AutomationAlertTest alertTest =
                new AutomationAlertTest(
                        "alertTest", AbstractAutomationTest.OnFail.WARN.toString(), job);
        alertTest.getData().setOnFail(AbstractAutomationTest.OnFail.WARN);
        alertTest.getData().setScanRuleId(alertData.getScanRuleId());
        alertTest.getData().setAlertName(alertData.getAlertName());
        alertTest.getData().setAction(AutomationAlertTest.ACTION_PASS_IF_ABSENT);
        alertTest.getData().setUrl(alertData.getUrl());
        alertTest.getData().setMethod(alertData.getMethod());
        alertTest.getData().setAttack(alertData.getAttack());
        alertTest.getData().setParam(alertData.getParam());
        alertTest.getData().setEvidence(alertData.getEvidence());
        alertTest.getData().setConfidence(alertData.getConfidence());
        alertTest.getData().setRisk(alertData.getRisk());
        alertTest.getData().setOtherInfo(alertData.getOtherInfo());

        return alertTest;
    }
}
