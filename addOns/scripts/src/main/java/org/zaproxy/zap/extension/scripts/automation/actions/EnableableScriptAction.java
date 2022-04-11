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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;

public class EnableableScriptAction extends ScriptAction {

    private final String name;
    private final boolean enabled;
    private static final List<String> DISABLED_FIELDS =
            Arrays.asList(
                    ScriptJobDialog.SCRIPT_ENGINE_PARAM,
                    ScriptJobDialog.SCRIPT_FILE_PARAM,
                    ScriptJobDialog.SCRIPT_TARGET_PARAM);

    public EnableableScriptAction(String name, boolean enabled, ScriptJobParameters parameters) {
        super(parameters);
        this.name = name;
        this.enabled = enabled;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "scripts.automation.dialog.summary." + name, parameters.getName());
    }

    @Override
    public List<String> verifyParameters(
            String jobName, ScriptJobParameters params, AutomationProgress progress) {
        List<String> list = new ArrayList<>();
        String issue;

        if (StringUtils.isEmpty(params.getName())) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.scriptNameIsNull", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        }

        // Note dont warn/error if script not currently in ZAP - it might be added by another job
        if (!StringUtils.isEmpty(params.getFile())) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.warn.fileNotNeeded", params.getName());
            list.add(issue);
            if (progress != null) {
                progress.warn(issue);
            }
        }

        return list;
    }

    @Override
    public List<String> getSupportedScriptTypes() {
        return getEnableableScriptTypes();
    }

    @Override
    public List<String> getDisabledFields() {
        return DISABLED_FIELDS;
    }

    @Override
    public void runJob(String jobName, AutomationEnvironment env, AutomationProgress progress) {
        ScriptWrapper script = findScript();
        if (script == null) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptNameNotFound",
                            jobName,
                            parameters.getName()));
            return;
        }

        ScriptType scriptType = script.getType();
        if (!scriptType.isEnableable()) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeNotEnableable",
                            jobName,
                            parameters.getType()));
            return;
        }
        extScript.setEnabled(script, enabled);
    }
}
