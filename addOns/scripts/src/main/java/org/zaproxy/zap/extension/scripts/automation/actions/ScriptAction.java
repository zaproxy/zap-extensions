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

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;

public abstract class ScriptAction {

    protected final Logger LOGGER = LogManager.getLogger(this.getClass());
    protected final ExtensionScript extScript;
    protected final ScriptJobParameters parameters;

    public ScriptAction(ScriptJobParameters parameters) {
        this.parameters = parameters;
        this.extScript = getExtScript();
    }

    protected ScriptWrapper findScript() {
        return this.extScript.getScript(parameters.getName());
    }

    protected boolean isScriptTypeSupported() {
        String scriptTypeLc = parameters.getType().toLowerCase(Locale.ROOT);
        return getSupportedScriptTypes().stream().anyMatch(st -> Objects.equals(st, scriptTypeLc));
    }

    protected boolean verifyScriptType(AutomationProgress progress) {
        if (parameters.getType() == null) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeIsNull", parameters.getName()));
            return false;
        }

        String scriptType = parameters.getType().toLowerCase();
        if (getSupportedScriptTypes().stream().noneMatch(st -> Objects.equals(st, scriptType))) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeNotSupported",
                            parameters.getName(),
                            scriptType,
                            getName(),
                            String.join(", ", getSupportedScriptTypes())));
            return false;
        }
        return true;
    }

    public static ExtensionScript getExtScript() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
    }

    public static List<ScriptWrapper> getAvailableScripts(String scriptType) {
        return getExtScript().getScripts(scriptType);
    }

    public static List<String> getAvailableScriptNames(String scriptType) {
        return getAvailableScripts(scriptType).stream()
                .map(s -> s.getName())
                .collect(Collectors.toList());
    }

    public static List<String> getAllScriptTypes() {
        return getExtScript().getScriptTypes().stream()
                .map(ScriptType::getName)
                .sorted()
                .collect(Collectors.toList());
    }

    public static List<String> getEnableableScriptTypes() {
        return getExtScript().getScriptTypes().stream()
                .filter(ScriptType::isEnableable)
                .map(ScriptType::getName)
                .sorted()
                .collect(Collectors.toList());
    }

    public static List<String> getScriptingEngines() {
        return getExtScript().getScriptingEngines().stream().sorted().collect(Collectors.toList());
    }

    public final void verifyParameters(String jobName, AutomationProgress progress) {
        this.verifyParameters(jobName, parameters, progress);
    }

    public abstract String getName();

    public abstract String getSummary();

    /**
     * Returns a list of issues with the parameters, one issue per line
     *
     * @param jobName The name of the job, used for logging
     * @param params The parameters to verify
     * @param progress The progress to update - may be null
     * @return
     */
    public abstract List<String> verifyParameters(
            String jobName, ScriptJobParameters params, AutomationProgress progress);

    public abstract List<String> getSupportedScriptTypes();

    public abstract void runJob(
            String jobName, AutomationEnvironment env, AutomationProgress progress);

    public abstract List<String> getDisabledFields();
}
