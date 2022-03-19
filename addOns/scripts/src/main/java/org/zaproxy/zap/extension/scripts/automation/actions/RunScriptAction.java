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

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobOutputListener;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;

public class RunScriptAction extends ScriptAction {

    public static final String NAME = "run";
    private static final List<String> SCRIPT_TYPES =
            Arrays.asList(ExtensionScript.TYPE_STANDALONE, ExtensionScript.TYPE_TARGETED);
    private static final List<String> DISABLED_FIELDS =
            Arrays.asList(
                    ScriptJobDialog.SCRIPT_ENGINE_PARAM,
                    ScriptJobDialog.SCRIPT_FILE_PARAM,
                    ScriptJobDialog.SCRIPT_TARGET_PARAM);

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
    public List<String> verifyParameters(
            String jobName, ScriptJobParameters params, AutomationProgress progress) {
        List<String> list = new ArrayList<>();
        String issue;
        String scriptType = params.getType();

        if (StringUtils.isEmpty(params.getName())) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.scriptNameIsNull", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        }

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

        if (ExtensionScript.TYPE_TARGETED.equals(scriptType)) {
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

            if (StringUtils.isEmpty(params.getTarget())) {
                issue =
                        Constant.messages.getString(
                                "scripts.automation.error.scriptTargetIsNull", jobName);
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
        return SCRIPT_TYPES;
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

    @Override
    public void runJob(String jobName, AutomationEnvironment env, AutomationProgress progress) {
        ScriptJobOutputListener scriptJobOutputListener =
                new ScriptJobOutputListener(progress, parameters.getName());
        try {
            extScript.addScriptOutputListener(scriptJobOutputListener);
            ScriptWrapper script = findScript();
            if (script == null) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.scriptNameNotFound",
                                jobName,
                                parameters.getName()));
                return;
            }
            if (parameters.getType().equals(ExtensionScript.TYPE_TARGETED)) {
                URI targetUri = new URI(parameters.getTarget(), true);
                SiteNode siteNode =
                        Model.getSingleton().getSession().getSiteTree().findNode(targetUri);
                if (siteNode == null) {
                    progress.error(
                            Constant.messages.getString(
                                    "scripts.automation.error.scriptTargetNotFound",
                                    jobName,
                                    parameters.getTarget()));
                    return;
                }

                HttpMessage httpMessage = siteNode.getHistoryReference().getHttpMessage();
                extScript.invokeTargetedScript(script, httpMessage);
            } else {
                extScript.invokeScript(script);
            }
            scriptJobOutputListener.flush();
        } catch (Exception e) {
            LOGGER.error(e);
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.scriptError",
                            jobName,
                            parameters.getName(),
                            e.getMessage()));
        } finally {
            extScript.removeScriptOutputListener(scriptJobOutputListener);
        }
    }
}
