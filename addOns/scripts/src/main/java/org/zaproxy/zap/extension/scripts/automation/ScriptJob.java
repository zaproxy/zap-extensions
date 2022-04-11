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
package org.zaproxy.zap.extension.scripts.automation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.scripts.automation.actions.AddScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.DisableScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.EnableScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.RemoveScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.ScriptAction;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;

public class ScriptJob extends AutomationJob {

    public static final String JOB_NAME = "script";
    public static final String PARAM_ACTION = "action";
    public static final String PARAM_SCRIPT_NAME = "scriptName";
    protected static final Map<String, Function<ScriptJobParameters, ScriptAction>> ACTIONS =
            new HashMap<String, Function<ScriptJobParameters, ScriptAction>>() {
                private static final long serialVersionUID = 1L;

                {
                    put(AddScriptAction.NAME.toLowerCase(), AddScriptAction::new);
                    put(RemoveScriptAction.NAME.toLowerCase(), RemoveScriptAction::new);
                    put(RunScriptAction.NAME.toLowerCase(), RunScriptAction::new);
                    put(EnableScriptAction.NAME.toLowerCase(Locale.ROOT), EnableScriptAction::new);
                    put(
                            DisableScriptAction.NAME.toLowerCase(Locale.ROOT),
                            DisableScriptAction::new);
                }
            };

    private ScriptJobData data;
    private ScriptJobParameters parameters = new ScriptJobParameters();

    public ScriptJob() {
        this.data = new ScriptJobData(this, parameters);
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        Map<?, ?> jobData = this.getJobData();
        if (jobData != null) {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) jobData.get("parameters"),
                    this.parameters,
                    this.getName(),
                    null,
                    progress);
        }

        ScriptAction scriptAction = createScriptAction(progress);
        if (scriptAction != null) {
            scriptAction.verifyParameters(this.getName(), progress);
        }
    }

    @Override
    public void applyParameters(AutomationProgress progress) {
        // Doesnt need to do anything
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        ScriptAction scriptAction = createScriptAction(progress);
        if (scriptAction != null) {
            progress.info(
                    Constant.messages.getString(
                            "scripts.automation.info.startAction",
                            this.getName(),
                            scriptAction.getName()));
            scriptAction.runJob(this.getName(), env, progress);
        }
    }

    @Override
    public String getType() {
        return JOB_NAME;
    }

    @Override
    public String getSummary() {
        ScriptAction scriptAction = createScriptAction(new AutomationProgress());
        if (scriptAction != null) {
            return scriptAction.getSummary();
        }
        return Constant.messages.getString("scripts.automation.dialog.summary.noAction");
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
    public ScriptJobData getData() {
        return data;
    }

    @Override
    public Map<String, String> getCustomConfigParameters() {
        Map<String, String> map = super.getCustomConfigParameters();
        map.put(PARAM_ACTION, "");
        map.put(PARAM_SCRIPT_NAME, "");
        return map;
    }

    @Override
    public void showDialog() {
        new ScriptJobDialog(this).setVisible(true);
    }

    @Override
    public String getTemplateDataMin() {
        return ExtensionScriptAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    @Override
    public String getTemplateDataMax() {
        return ExtensionScriptAutomation.getResourceAsString(this.getType() + "-max.yaml");
    }

    public ScriptAction createScriptAction(AutomationProgress progress) {
        return createScriptAction(getData().getParameters(), progress);
    }

    public static ScriptAction createScriptAction(
            ScriptJobParameters parameters, AutomationProgress progress) {
        if (parameters.getAction() == null) {
            if (progress != null) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.actionNull", validActionsAsString()));
            }
            return null;
        }

        String action = parameters.getAction().toLowerCase();
        Function<ScriptJobParameters, ScriptAction> scriptActionFactory = ACTIONS.get(action);
        if (scriptActionFactory != null) {
            return scriptActionFactory.apply(parameters);
        }

        if (progress != null) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.actionNotDefined",
                            action,
                            validActionsAsString()));
        }

        return null;
    }

    private static String validActionsAsString() {
        return String.join(",", ACTIONS.keySet());
    }

    public static List<String> validActions() {
        return ACTIONS.keySet().stream().collect(Collectors.toList());
    }

    public static List<String> validScriptTypesForAction(String action) {
        ScriptAction scriptAction =
                createScriptAction(new ScriptJobParameters(action), new AutomationProgress());
        if (scriptAction != null) {
            return scriptAction.getSupportedScriptTypes();
        }
        return new ArrayList<>();
    }
}
