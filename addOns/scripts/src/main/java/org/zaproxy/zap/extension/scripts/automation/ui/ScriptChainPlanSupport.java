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

import java.io.File;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.actions.AddScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.ScriptAction;

/** Plan and ZAP script names for the chain shuttle source catalog. */
final class ScriptChainPlanSupport {

    private ScriptChainPlanSupport() {}

    static List<String> sourceCatalog(ScriptJob currentJob) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (ScriptWrapper script :
                ScriptAction.getAvailableScripts(ExtensionScript.TYPE_STANDALONE)) {
            if (RunScriptAction.isZestStandaloneChainScript(script)) {
                names.add(script.getName());
            }
        }
        AutomationPlan plan = currentJob.getPlan();
        if (plan != null) {
            List<AutomationJob> jobs = plan.getJobs();
            int currentIndex = jobs.indexOf(currentJob);
            if (currentIndex >= 0) {
                for (int i = 0; i < currentIndex; i++) {
                    AutomationJob job = jobs.get(i);
                    if (!ScriptJob.JOB_NAME.equals(job.getType())) {
                        continue;
                    }
                    ScriptJobParameters parameters = parametersForPriorStandaloneAdd(job);
                    if (parameters != null && isZestPlanAddScript(parameters)) {
                        names.add(resolveAddScriptName(parameters));
                    }
                }
            }
        }
        return List.copyOf(names);
    }

    private static ScriptJobParameters parametersForPriorStandaloneAdd(AutomationJob planJob) {
        if (planJob instanceof ScriptJob scriptJob) {
            ScriptJobParameters parameters = scriptJob.getParameters();
            return isStandaloneAdd(parameters.getAction(), parameters.getType())
                    ? parameters
                    : null;
        }
        Map<?, ?> jobData = planJob.getJobData();
        if (jobData == null) {
            return null;
        }
        Object parameters = jobData.get("parameters");
        if (!(parameters instanceof Map<?, ?> paramsMap)) {
            return null;
        }
        if (!isStandaloneAdd(
                Objects.toString(paramsMap.get("action"), ""),
                Objects.toString(paramsMap.get("type"), ""))) {
            return null;
        }
        ScriptJobParameters params = new ScriptJobParameters();
        params.setAction(Objects.toString(paramsMap.get("action"), null));
        params.setType(Objects.toString(paramsMap.get("type"), null));
        params.setEngine(Objects.toString(paramsMap.get("engine"), null));
        params.setName(Objects.toString(paramsMap.get("name"), null));
        params.setSource(Objects.toString(paramsMap.get("source"), null));
        return params;
    }

    private static boolean isStandaloneAdd(String action, String type) {
        return AddScriptAction.NAME.equalsIgnoreCase(action)
                && ExtensionScript.TYPE_STANDALONE.equals(type);
    }

    private static boolean isZestPlanAddScript(ScriptJobParameters parameters) {
        String resolvedName = resolveAddScriptName(parameters);
        if (StringUtils.isBlank(resolvedName)) {
            return false;
        }
        ExtensionScript extScript = ScriptAction.getExtScript();
        String engine = parameters.getEngine();
        if (StringUtils.isBlank(engine)) {
            engine = RunScriptAction.inferEngineNameFromSource(extScript, parameters.getSource());
        }
        ScriptWrapper script = extScript.getScript(resolvedName);
        if (script != null) {
            boolean registryZest = RunScriptAction.isZestStandaloneChainScript(script);
            if (StringUtils.isNotBlank(engine)) {
                return registryZest && RunScriptAction.isZestEngine(engine);
            }
            return registryZest;
        }
        return RunScriptAction.isZestEngine(engine);
    }

    private static String resolveAddScriptName(ScriptJobParameters parameters) {
        if (StringUtils.isNotBlank(parameters.getName())) {
            return parameters.getName();
        }
        String source = parameters.getSource();
        if (StringUtils.isBlank(source)) {
            return null;
        }
        return new File(source).getName();
    }
}
