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

import java.io.File;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;

public class AddScriptAction extends ScriptAction {

    public static final String NAME = "add";
    private static final List<String> DISABLED_FIELDS =
            Arrays.asList(ScriptJobDialog.SCRIPT_TARGET_PARAM);

    public AddScriptAction(ScriptJobParameters parameters) {
        super(parameters);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "scripts.automation.dialog.summary.add", parameters.getName());
    }

    @Override
    public List<String> verifyParameters(
            String jobName, ScriptJobParameters params, AutomationProgress progress) {
        List<String> list = new ArrayList<>();
        String issue;
        String scriptType = parameters.getType();
        String filename = params.getFile();

        if (scriptType == null) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeIsNull", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        } else if (!this.isScriptTypeSupported()) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.scriptTypeNotSupported",
                            jobName,
                            scriptType,
                            getName(),
                            String.join(", ", getSupportedScriptTypes()));
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        }

        if (StringUtils.isEmpty(filename)) {
            issue = Constant.messages.getString("scripts.automation.error.file.missing", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        } else {
            File f = new File(filename);
            if (!f.canRead()) {
                issue =
                        Constant.messages.getString(
                                "scripts.automation.error.file.cannotRead",
                                jobName,
                                f.getAbsolutePath());
                list.add(issue);
                if (progress != null) {
                    progress.error(issue);
                }
            } else if (!f.isFile()) {
                issue =
                        Constant.messages.getString(
                                "scripts.automation.error.file.notFile",
                                jobName,
                                f.getAbsolutePath());
                list.add(issue);
                if (progress != null) {
                    progress.error(issue);
                }
            }
        }

        if (getEngineWrapper(params) == null) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.scriptEngineNotFound",
                            jobName,
                            this.parameters.getEngine());
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        }

        return list;
    }

    @Override
    public List<String> getSupportedScriptTypes() {
        return getAllScriptTypes();
    }

    @Override
    public List<String> getDisabledFields() {
        return DISABLED_FIELDS;
    }

    private ScriptEngineWrapper getEngineWrapper(ScriptJobParameters params) {
        ScriptEngineWrapper se = null;
        try {
            se = extScript.getEngineWrapper(this.parameters.getEngine());
        } catch (Exception e) {
            String filename = params.getFile();
            if (filename != null && filename.contains(".")) {
                try {
                    se =
                            extScript.getEngineWrapper(
                                    extScript.getEngineNameForExtension(
                                            filename.substring(filename.indexOf(".") + 1)
                                                    .toLowerCase(Locale.ROOT)));
                } catch (InvalidParameterException e1) {
                    // Ignore - will return null below
                }
            }
        }
        return se;
    }

    private ScriptWrapper getScriptWrapper() {
        ScriptWrapper sw = new ScriptWrapper();
        sw.setName(this.parameters.getName());
        if (this.parameters.getFile() != null) {
            File f = new File(this.parameters.getFile());
            sw.setFile(f);
            if (StringUtils.isEmpty(sw.getName())) {
                sw.setName(f.getName());
            }
        }
        sw.setType(extScript.getScriptType(this.parameters.getType()));
        sw.setEngine(getEngineWrapper(this.parameters));
        sw.setEnabled(true);
        return sw;
    }

    @Override
    public void runJob(String jobName, AutomationEnvironment env, AutomationProgress progress) {
        ScriptWrapper sw = this.getScriptWrapper();
        try {
            extScript.loadScript(sw);
            ScriptWrapper existingScript = extScript.getScript(sw.getName());
            if (existingScript != null) {
                // Always replace an existing script with the same name
                extScript.removeScript(existingScript);
                progress.info(
                        Constant.messages.getString(
                                "scripts.automation.info.add.replace", jobName, sw.getName()));
            }
            extScript.addScript(sw);
        } catch (IOException e) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.add.failed", jobName, e.getMessage()));
        }
    }
}
