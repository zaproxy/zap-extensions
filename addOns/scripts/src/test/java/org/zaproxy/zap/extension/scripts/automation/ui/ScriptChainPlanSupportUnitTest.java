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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.ExtensionScriptsUI;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.actions.AddScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit tests for {@link ScriptChainPlanSupport}. */
class ScriptChainPlanSupportUnitTest extends TestUtils {

    private static ExtensionLoader extensionLoader;
    private ExtensionScript extScript;

    @BeforeAll
    static void setUpControl() {
        Constant.messages = new I18N(Locale.ENGLISH);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @BeforeEach
    void setUpEach() {
        extScript = mock(ExtensionScript.class);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extScript);
        lenient().when(extScript.getScripts(ExtensionScript.TYPE_STANDALONE)).thenReturn(List.of());
    }

    @Test
    void shouldBuildSourceCatalogFromZapAndPriorPlanAdds() {
        ScriptWrapper zapScript = zestStandaloneWrapper("login");
        given(extScript.getScripts(ExtensionScript.TYPE_STANDALONE)).willReturn(List.of(zapScript));

        ScriptJob runChain = runJob();
        AutomationPlan plan = new AutomationPlan();
        plan.addJob(zestAdd("login"));
        plan.addJob(zestAdd("yaml-only"));
        plan.addJob(runChain);

        assertThat(ScriptChainPlanSupport.sourceCatalog(runChain), contains("login", "yaml-only"));
    }

    @Test
    void shouldFilterSourceCatalogToZestStandaloneAdds() {
        given(extScript.getEngineNameForExtension("zst"))
                .willReturn(RunScriptAction.ZEST_ENGINE_NAME);

        ScriptJob addZest = zestAdd("login");
        ScriptJob addGraal = scriptJob("add-graal", AddScriptAction.NAME, "graal-script");
        addGraal.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        addGraal.getParameters().setEngine("Graal.js");

        ScriptJob addTargeted = scriptJob("add-targeted", AddScriptAction.NAME, "targeted");
        addTargeted.getParameters().setType(ExtensionScriptsUI.TYPE_TARGETED);

        ScriptJob addFromSource = scriptJob("add-zest", AddScriptAction.NAME, "");
        addFromSource.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        addFromSource.getParameters().setSource("/scripts/login.zst");

        ScriptJob addNav = scriptJob("add-nav", AddScriptAction.NAME, "");
        addNav.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        addNav.getParameters().setEngine("Zest : " + RunScriptAction.ZEST_ENGINE_NAME);
        addNav.getParameters()
                .setSource("/scripts/zap-rec-demo.testfire.net2026-02-09-09-58-36.zst");

        ScriptJob runChain = runJob();
        AutomationPlan plan = new AutomationPlan();
        plan.addJob(addZest);
        plan.addJob(addGraal);
        plan.addJob(addTargeted);
        plan.addJob(addFromSource);
        plan.addJob(addNav);
        plan.addJob(runChain);

        assertThat(
                ScriptChainPlanSupport.sourceCatalog(runChain),
                contains("login", "login.zst", "zap-rec-demo.testfire.net2026-02-09-09-58-36.zst"));
    }

    @Test
    void shouldResolvePriorAddSourceToRegisteredScriptName() {
        ScriptWrapper registered = zestStandaloneWrapper("my-login");
        registered.setFile(new File("/scripts/login.zst"));
        given(extScript.getScripts(ExtensionScript.TYPE_STANDALONE))
                .willReturn(List.of(registered));
        given(extScript.getScript("my-login")).willReturn(registered);

        ScriptJob addFromSource = scriptJob("add-zest", AddScriptAction.NAME, "");
        addFromSource.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        addFromSource.getParameters().setSource("/scripts/login.zst");

        ScriptJob runChain = runJob();
        AutomationPlan plan = new AutomationPlan();
        plan.addJob(addFromSource);
        plan.addJob(runChain);

        assertThat(ScriptChainPlanSupport.sourceCatalog(runChain), contains("my-login"));
    }

    @Test
    void shouldExcludeAddJobsAfterRunJobInPlan() {
        ScriptJob runChain = runJob();
        AutomationPlan plan = new AutomationPlan();
        plan.addJob(runChain);
        plan.addJob(zestAdd("first"));
        plan.addJob(zestAdd("second"));

        assertThat(ScriptChainPlanSupport.sourceCatalog(runChain), is(empty()));
    }

    private static ScriptJob zestAdd(String name) {
        ScriptJob job = scriptJob("add-" + name, AddScriptAction.NAME, name);
        job.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        job.getParameters().setEngine(RunScriptAction.ZEST_ENGINE_NAME);
        return job;
    }

    private static ScriptJob runJob() {
        ScriptJob job = scriptJob("run-chain", RunScriptAction.NAME, "");
        job.getParameters().setType(ExtensionScript.TYPE_STANDALONE);
        return job;
    }

    private static ScriptJob scriptJob(String jobName, String action, String scriptName) {
        ScriptJob job = new ScriptJob();
        job.setName(jobName);
        job.getData().setName(jobName);
        job.getParameters().setAction(action);
        job.getParameters().setName(scriptName);
        return job;
    }

    private static ScriptWrapper zestStandaloneWrapper(String name) {
        ScriptWrapper wrapper = new ScriptWrapper();
        wrapper.setName(name);
        wrapper.setEngineName(RunScriptAction.ZEST_ENGINE_NAME);
        wrapper.setType(new ScriptType(ExtensionScript.TYPE_STANDALONE, null, null, false));
        return wrapper;
    }
}
