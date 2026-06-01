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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.actions.AddScriptAction;

/** Plan and text helpers for script-chain fields in {@link ScriptJobDialog}. */
final class ScriptChainPlanSupport {

    private ScriptChainPlanSupport() {}

    static List<String> parseChainText(String text) {
        if (StringUtils.isBlank(text)) {
            return List.of();
        }
        return Arrays.stream(text.split("\\R"))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .toList();
    }

    static String formatChainText(List<String> chain) {
        if (chain == null || chain.isEmpty()) {
            return "";
        }
        return String.join("\n", chain);
    }

    static List<String> priorStandaloneAddScriptNames(ScriptJob currentJob) {
        List<String> names = new ArrayList<>();
        AutomationPlan plan = currentJob.getPlan();
        if (plan == null) {
            return names;
        }
        for (AutomationJob planJob : plan.getJobs()) {
            if (planJob == currentJob) {
                break;
            }
            if (!ScriptJob.JOB_NAME.equals(planJob.getType())) {
                continue;
            }
            ScriptJobParameters params = parametersFor(planJob);
            if (params == null) {
                continue;
            }
            if (!AddScriptAction.NAME.equalsIgnoreCase(params.getAction())) {
                continue;
            }
            if (!ExtensionScript.TYPE_STANDALONE.equals(params.getType())) {
                continue;
            }
            String name = params.getName();
            if (StringUtils.isNotBlank(name)) {
                names.add(name);
            }
        }
        return names;
    }

    private static ScriptJobParameters parametersFor(AutomationJob planJob) {
        if (planJob instanceof ScriptJob scriptJob) {
            return scriptJob.getParameters();
        }
        Map<?, ?> jobData = planJob.getJobData();
        if (jobData == null) {
            return null;
        }
        Object parameters = jobData.get(ScriptJob.PARAM_PARAMETERS);
        if (!(parameters instanceof LinkedHashMap<?, ?> paramsMap)) {
            return null;
        }
        ScriptJobParameters params = new ScriptJobParameters();
        params.setAction(stringValue(paramsMap.get(ScriptJob.PARAM_ACTION)));
        params.setType(stringValue(paramsMap.get(ScriptJob.PARAM_TYPE)));
        params.setName(stringValue(paramsMap.get(ScriptJob.PARAM_NAME)));
        return params;
    }

    private static String stringValue(Object value) {
        return value == null ? null : value.toString();
    }
}
