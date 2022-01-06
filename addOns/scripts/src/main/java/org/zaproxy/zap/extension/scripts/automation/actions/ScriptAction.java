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
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
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

    protected ScriptWrapper findScript(AutomationProgress progress) {
        if (!verifyScriptType(progress)) {
            return null;
        }

        List<ScriptWrapper> scripts = getAvailableScripts(parameters.getType());
        Optional<ScriptWrapper> script =
                scripts.stream()
                        .filter(s -> Objects.equals(s.getName(), parameters.getName()))
                        .findFirst();
        if (!script.isPresent()) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptNameNotFound",
                            ExtensionScript.TYPE_STANDALONE,
                            parameters.getName()));
            return null;
        }
        return script.get();
    }

    protected boolean verifyScriptType(AutomationProgress progress) {
        if (parameters.getType() == null) {
            progress.error(
                    Constant.messages.getString("scripts.automation.error.scriptTypeIsNull"));
            return false;
        }

        String scriptType = parameters.getType().toLowerCase();
        if (!getSupportedScriptTypes().stream().anyMatch(st -> Objects.equals(st, scriptType))) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeNotSupported",
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

    public abstract String getName();

    public abstract String getSummary();

    public abstract void verifyParameters(AutomationProgress progress);

    public abstract List<String> getSupportedScriptTypes();

    public abstract void runJob(AutomationEnvironment env, AutomationProgress progress);
}
