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
package org.zaproxy.zap.extension.scripts.automation.actions;

import java.util.Arrays;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobOutputListener;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;

public class RunScriptAction extends ScriptAction {

    public static final String NAME = "run";
    private static final List<String> SCRIPT_TYPES = Arrays.asList(ExtensionScript.TYPE_STANDALONE);

    public RunScriptAction(ScriptJobParameters parameters) {
        super(parameters);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "scripts.automation.dialog.summary.run", parameters.getName());
    }

    @Override
    public void verifyParameters(AutomationProgress progress) {
        findScript(progress);
    }

    @Override
    public List<String> getSupportedScriptTypes() {
        return SCRIPT_TYPES;
    }

    @Override
    public void runJob(AutomationEnvironment env, AutomationProgress progress) {
        ScriptJobOutputListener scriptJobOutputListener =
                new ScriptJobOutputListener(progress, parameters.getName());
        try {
            extScript.addScriptOutputListener(scriptJobOutputListener);
            ScriptWrapper script = findScript(progress);
            if (script == null) {
                return;
            }
            extScript.invokeScript(script);
            scriptJobOutputListener.flush();
        } catch (Exception e) {
            LOGGER.error(e);
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptError",
                            parameters.getName(),
                            e.getMessage()));
        } finally {
            extScript.removeScriptOutputListener(scriptJobOutputListener);
        }
    }
}
