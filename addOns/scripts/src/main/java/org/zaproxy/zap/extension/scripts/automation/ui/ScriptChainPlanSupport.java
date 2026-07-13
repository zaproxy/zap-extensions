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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
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

    static Set<String> sourceCatalog(ScriptJob currentJob) {
        LinkedHashSet<String> names = new LinkedHashSet<>();
        Map<String, String> namesByFile = new HashMap<>();
        for (ScriptWrapper script :
                ScriptAction.getAvailableScripts(ExtensionScript.TYPE_STANDALONE)) {
            File file = script.getFile();
            if (file != null) {
                namesByFile.putIfAbsent(file.getName(), script.getName());
            }
            if (RunScriptAction.isZestStandaloneChainScript(script)) {
                names.add(script.getName());
            }
        }
        AutomationPlan plan = currentJob.getPlan();
        for (AutomationJob job : plan.getJobs().subList(0, plan.getJobs().indexOf(currentJob))) {
            if (!(job instanceof ScriptJob scriptJob)) {
                continue;
            }
            ScriptJobParameters parameters = scriptJob.getParameters();
            if (!AddScriptAction.NAME.equalsIgnoreCase(parameters.getAction())
                    || !ExtensionScript.TYPE_STANDALONE.equals(parameters.getType())) {
                continue;
            }
            if (isZestPlanAddScript(parameters, namesByFile)) {
                names.add(resolveAddScriptName(parameters, namesByFile));
            }
        }
        return Collections.unmodifiableSet(names);
    }

    private static boolean isZestPlanAddScript(
            ScriptJobParameters parameters, Map<String, String> namesByFile) {
        String resolvedName = resolveAddScriptName(parameters, namesByFile);
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

    private static String resolveAddScriptName(
            ScriptJobParameters parameters, Map<String, String> namesByFile) {
        if (StringUtils.isNotBlank(parameters.getName())) {
            return parameters.getName();
        }
        String source = parameters.getSource();
        if (StringUtils.isBlank(source)) {
            return null;
        }
        String fileName = new File(source).getName();
        String registeredName = namesByFile.get(fileName);
        return registeredName != null ? registeredName : fileName;
    }
}
