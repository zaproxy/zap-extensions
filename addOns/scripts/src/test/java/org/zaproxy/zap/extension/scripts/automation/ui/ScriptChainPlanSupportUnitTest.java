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
package org.zaproxy.zap.extension.scripts.automation.ui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.actions.AddScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link ScriptChainPlanSupport}. */
class ScriptChainPlanSupportUnitTest extends TestUtils {

    @Test
    void shouldParseChainLinesTrimmingBlankLines() {
        assertThat(
                ScriptChainPlanSupport.parseChainText(" login \n\n checkout \r\n "),
                contains("login", "checkout"));
    }

    @Test
    void shouldReturnEmptyListForBlankChainText() {
        assertThat(ScriptChainPlanSupport.parseChainText("  \n  "), is(empty()));
    }

    @Test
    void shouldFormatChainAsNewlineSeparatedNames() {
        assertThat(ScriptChainPlanSupport.formatChainText(List.of("a", "b")), is("a\nb"));
    }

    @Test
    void shouldCollectPriorStandaloneAddScriptNamesOnly() {
        ScriptJob addLogin = scriptJob("add-login", AddScriptAction.NAME, "login");
        addLogin.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        addLogin.getParameters().setName("login");

        ScriptJob addTargeted = scriptJob("add-targeted", AddScriptAction.NAME, "targeted-script");
        addTargeted.getParameters().setType(ExtensionScript.TYPE_TARGETED);
        addTargeted.getParameters().setName("targeted-script");

        ScriptJob runChain = scriptJob("run-chain", RunScriptAction.NAME, "");
        runChain.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        runChain.getParameters().setChain(List.of("login"));

        AutomationPlan plan = new AutomationPlan();
        plan.addJob(addLogin);
        plan.addJob(addTargeted);
        plan.addJob(runChain);

        assertThat(
                ScriptChainPlanSupport.priorStandaloneAddScriptNames(runChain), contains("login"));
    }

    @Test
    void shouldReadPriorAddFromJobDataWhenNotScriptJobInstance() {
        ScriptJob runChain = scriptJob("run", RunScriptAction.NAME, "");
        runChain.getParameters().setType(ExtensionScript.TYPE_STANDALONE);

        AutomationJob priorAdd = new StubScriptPlanJob();
        LinkedHashMap<String, Object> parameters = new LinkedHashMap<>();
        parameters.put(ScriptJob.PARAM_ACTION, AddScriptAction.NAME);
        parameters.put(ScriptJob.PARAM_TYPE, ExtensionScript.TYPE_STANDALONE);
        parameters.put(ScriptJob.PARAM_NAME, "from-yaml");
        LinkedHashMap<String, Object> jobData = new LinkedHashMap<>();
        jobData.put(ScriptJob.PARAM_PARAMETERS, parameters);
        priorAdd.setJobData(jobData);

        AutomationPlan plan = new AutomationPlan();
        plan.addJob(priorAdd);
        plan.addJob(runChain);

        assertThat(
                ScriptChainPlanSupport.priorStandaloneAddScriptNames(runChain),
                contains("from-yaml"));
    }

    private static final class StubScriptPlanJob extends AutomationJob {
        @Override
        public String getType() {
            return ScriptJob.JOB_NAME;
        }

        @Override
        public Order getOrder() {
            return Order.CONFIGS;
        }

        @Override
        public Object getParamMethodObject() {
            return null;
        }

        @Override
        public String getParamMethodName() {
            return null;
        }

        @Override
        public void runJob(AutomationEnvironment env, AutomationProgress progress) {}
    }

    private static ScriptJob scriptJob(String jobName, String action, String scriptName) {
        ScriptJobParameters params = new ScriptJobParameters(action);
        params.setName(scriptName);
        ScriptJob job = new ScriptJob();
        job.setName(jobName);
        job.getData().setName(jobName);
        job.getParameters().setAction(action);
        job.getParameters().setName(scriptName);
        return job;
    }
}
