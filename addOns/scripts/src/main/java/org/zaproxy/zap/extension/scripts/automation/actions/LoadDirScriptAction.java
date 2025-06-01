/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;

public class LoadDirScriptAction extends ScriptAction {

    public static final String NAME = "loaddir";
    private static final List<String> DISABLED_FIELDS =
            Arrays.asList(
                    ScriptJobDialog.SCRIPT_TYPE_PARAM,
                    ScriptJobDialog.SCRIPT_ENGINE_PARAM,
                    ScriptJobDialog.SCRIPT_NAME_PARAM,
                    ScriptJobDialog.SCRIPT_IS_INLINE_PARAM,
                    ScriptJobDialog.SCRIPT_TARGET_PARAM);

    public LoadDirScriptAction(ScriptJobParameters parameters) {
        super(parameters);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getSummary() {
        return Constant.messages.getString(
                "scripts.automation.dialog.summary.loaddir", parameters.getName());
    }

    @Override
    public List<String> verifyParameters(
            String jobName, ScriptJobParameters params, AutomationProgress progress) {
        List<String> list = new ArrayList<>();
        String issue;
        String path = params.getSource();

        if (StringUtils.isEmpty(path)) {
            issue = Constant.messages.getString("scripts.automation.error.file.missing", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        } else if (JobUtils.isAbsoluteLiteralPath(path)) {
            // Cannot check relative paths or ones that contain vars at this point
            File f = new File(path);
            if (JobUtils.isAbsoluteLiteralPath(path))
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
                } else if (!f.isDirectory()) {
                    issue =
                            Constant.messages.getString(
                                    "scripts.automation.error.file.notDir",
                                    jobName,
                                    f.getAbsolutePath());
                    list.add(issue);
                    if (progress != null) {
                        progress.error(issue);
                    }
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

    private int addScriptsFromDir(
            File dir, ScriptType type, String jobName, AutomationProgress progress) {
        int addedScripts = 0;
        File typeDir = new File(dir, type.getName());
        if (typeDir.exists()) {
            for (File f : typeDir.listFiles()) {
                int dotIndex = f.getName().lastIndexOf(".");
                if (dotIndex < 0) {
                    // Ignore files with no extension
                    continue;
                }
                String ext = f.getName().substring(dotIndex + 1);
                String engineName = extScript.getEngineNameForExtension(ext);

                if (engineName != null) {
                    StringWriter writer = new StringWriter();
                    try {
                        ScriptAction.getExtScript().addWriter(writer);

                        String scriptName = f.getName();
                        ScriptWrapper sw =
                                new ScriptWrapper(
                                        scriptName,
                                        "",
                                        extScript.getEngineWrapper(engineName),
                                        type,
                                        true,
                                        f);
                        extScript.loadScript(sw);
                        extScript.addScript(sw, false);
                        addedScripts++;

                        progress.info(
                                Constant.messages.getString(
                                        "scripts.automation.info.loadDir.added",
                                        jobName,
                                        type.getName() + "/" + scriptName));

                        String scriptOutput = writer.toString();
                        if (scriptOutput.indexOf("Error") > 0) {
                            // A bit nasty, but no better options right now?
                            progress.error(
                                    Constant.messages.getString(
                                            "scripts.automation.info.script.output",
                                            jobName,
                                            writer.toString()));
                        } else if (scriptOutput.length() > 0) {
                            progress.info(
                                    Constant.messages.getString(
                                            "scripts.automation.info.script.output",
                                            jobName,
                                            writer.toString()));
                        }
                    } catch (Exception e) {
                        progress.error(
                                Constant.messages.getString(
                                        "scripts.automation.error.loadDir.failed",
                                        jobName,
                                        f.getAbsolutePath(),
                                        e.getMessage()));
                    } finally {
                        ScriptAction.getExtScript().removeWriter(writer);
                    }
                } else {
                    LOGGER.debug("Ignoring {}", f.getName());
                }
            }
        }
        return addedScripts;
    }

    @Override
    public void runJob(String jobName, AutomationEnvironment env, AutomationProgress progress) {
        int addedScripts = 0;
        File dir = new File(this.parameters.getSource());

        for (ScriptType type : extScript.getScriptTypes()) {
            addedScripts += addScriptsFromDir(dir, type, jobName, progress);
        }
        progress.info(
                Constant.messages.getString(
                        "scripts.automation.info.loadDir.loaded",
                        jobName,
                        this.parameters.getSource(),
                        addedScripts));
    }
}
