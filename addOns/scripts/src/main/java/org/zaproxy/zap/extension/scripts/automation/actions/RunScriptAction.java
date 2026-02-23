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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
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
import org.zaproxy.zap.users.User;

public class RunScriptAction extends ScriptAction {

    public static final String NAME = "run";
    private static final String ZEST_ENGINE_NAME = "Mozilla Zest";
    private static final String EXTENSION_ZEST_NAME = "ExtensionZest";
    private static final String RUN_NAME_CHAIN_PREFIX = "chain_";
    private static final List<String> SCRIPT_TYPES =
            Arrays.asList(ExtensionScript.TYPE_STANDALONE, ExtensionScript.TYPE_TARGETED);
    private static final List<String> DISABLED_FIELDS =
            Arrays.asList(
                    ScriptJobDialog.SCRIPT_ENGINE_PARAM,
                    ScriptJobDialog.SCRIPT_INLINE_PARAM,
                    ScriptJobDialog.SCRIPT_IS_INLINE_PARAM,
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

        boolean hasName = StringUtils.isNotEmpty(params.getName());
        boolean hasChain = params.getChain() != null && !params.getChain().isEmpty();

        if (hasName && hasChain) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.warn.chainAndNameBothSpecified", jobName);
            list.add(issue);
            if (progress != null) {
                progress.warn(issue);
            }
        } else if (!hasName && !hasChain) {
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
        } else if (hasChain && !ExtensionScript.TYPE_STANDALONE.equals(scriptType)) {
            issue =
                    Constant.messages.getString(
                            "scripts.automation.error.chainRequiresStandalone", jobName);
            list.add(issue);
            if (progress != null) {
                progress.error(issue);
            }
        }
        // Script/chain existence not validated here; chain validated at runtime in runScriptChain()
        if (!StringUtils.isEmpty(params.getSource())) {
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
            String filename = params.getSource();
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
        User user = null;
        if (StringUtils.isNotEmpty(this.parameters.getUser())) {
            user = env.getUser(this.parameters.getUser());
            if (user == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.job.baduser",
                                jobName,
                                this.parameters.getUser()));
                return;
            }
        }

        if (parameters.getChain() != null && !parameters.getChain().isEmpty()) {
            runScriptChain(jobName, user, progress);
        } else {
            ScriptWrapper script = findScript();
            if (script == null) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.scriptNameNotFound",
                                jobName,
                                parameters.getName()));
                return;
            }

            if (!getSupportedScriptTypes().contains(script.getTypeName())) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.scriptTypeNotSupported",
                                jobName,
                                script.getTypeName(),
                                getName(),
                                String.join(", ", getSupportedScriptTypes())));
                return;
            }

            if (parameters.getType().equals(ExtensionScript.TYPE_TARGETED)) {
                executeScriptWithOutputListener(
                        script,
                        progress,
                        () -> {
                            URI targetUri = new URI(parameters.getTarget(), true);
                            SiteNode siteNode =
                                    Model.getSingleton()
                                            .getSession()
                                            .getSiteTree()
                                            .findNode(targetUri);
                            if (siteNode == null) {
                                progress.error(
                                        Constant.messages.getString(
                                                "scripts.automation.error.scriptTargetNotFound",
                                                jobName,
                                                parameters.getTarget()));
                                return;
                            }

                            HttpMessage httpMessage =
                                    siteNode.getHistoryReference().getHttpMessage();
                            extScript.invokeTargetedScript(script, httpMessage);
                        },
                        (e) -> reportScriptError(progress, jobName, parameters, e));
            } else {
                setUserOnZestWrapper(script, user);
                executeScriptWithOutputListener(
                        script,
                        progress,
                        () -> extScript.invokeScript(script),
                        (e) -> reportScriptError(progress, jobName, parameters, e));
            }
        }
    }

    private void runScriptChain(String jobName, User user, AutomationProgress progress) {
        if (!ExtensionScript.TYPE_STANDALONE.equals(parameters.getType())) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.chainRequiresStandalone", jobName));
            return;
        }

        List<ScriptWrapper> scriptWrappers =
                validateChainScripts(parameters.getChain(), jobName, progress);
        if (scriptWrappers == null) {
            return; // Validation failed, error already reported
        }

        ScriptWrapper firstScript = scriptWrappers.get(0);
        String runName = RUN_NAME_CHAIN_PREFIX + firstScript.getName();
        ScriptWrapper chainScript;
        try {
            chainScript = getChainScriptViaReflection(scriptWrappers, runName);
        } catch (Exception e) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.chainPreparationFailed",
                            jobName,
                            e.getMessage()));
            return;
        }
        if (chainScript == null) {
            progress.error(
                    Constant.messages.getString(
                            "scripts.automation.error.chainReflectionFailed",
                            jobName,
                            firstScript.getName()));
            return;
        }

        setUserOnZestWrapper(chainScript, user);

        progress.info(
                Constant.messages.getString(
                        "scripts.automation.info.chainExecuting", jobName, scriptWrappers.size()));

        if (executeScriptWithOutputListener(
                chainScript,
                progress,
                () -> extScript.invokeScript(chainScript),
                (e) ->
                        progress.error(
                                Constant.messages.getString(
                                        "scripts.automation.error.chainExecutionFailed",
                                        jobName,
                                        e.getMessage())))) {
            progress.info(
                    Constant.messages.getString("scripts.automation.info.chainCompleted", jobName));
        }
    }

    /**
     * Runs the script with output listener setup/teardown and error handling.
     *
     * @param script the script to execute
     * @param progress the automation progress for output
     * @param executor the script execution logic
     * @param errorHandler the error handler for exceptions
     * @return true if execution succeeded, false otherwise
     */
    private boolean executeScriptWithOutputListener(
            ScriptWrapper script,
            AutomationProgress progress,
            ScriptExecutor executor,
            Consumer<Exception> errorHandler) {
        ScriptJobOutputListener scriptJobOutputListener =
                new ScriptJobOutputListener(progress, script.getName());
        try {
            extScript.addScriptOutputListener(scriptJobOutputListener);
            executor.execute();
            scriptJobOutputListener.flush();

            if (script.getLastException() != null) {
                errorHandler.accept(script.getLastException());
                return false;
            }
            return true;
        } catch (Exception e) {
            LOGGER.error(e, e);
            errorHandler.accept(e);
            return false;
        } finally {
            extScript.removeScriptOutputListener(scriptJobOutputListener);
        }
    }

    /** Script execution logic that may throw. */
    @FunctionalInterface
    private interface ScriptExecutor {
        void execute() throws Exception;
    }

    private static void reportScriptError(
            AutomationProgress progress,
            String jobName,
            ScriptJobParameters parameters,
            Exception e) {
        progress.error(
                Constant.messages.getString(
                        "scripts.automation.error.scriptError",
                        jobName,
                        parameters.getName(),
                        e.getMessage()));
    }

    private void setUserOnZestWrapper(ScriptWrapper script, User user) {
        if (user == null) {
            LOGGER.debug("User is null, skipping set user.");
            return;
        }
        if (!ZEST_ENGINE_NAME.equals(script.getEngineName())) {
            LOGGER.warn("Script engine is not Zest, skipping set user.");
            return;
        }

        try {
            script.getClass().getMethod("setUser", User.class).invoke(script, user);
        } catch (NoSuchMethodException
                | IllegalAccessException
                | InvocationTargetException
                | SecurityException e) {
            LOGGER.warn("Failed to set user on script wrapper", e);
        }
    }

    /**
     * Gets the chain script from Zest via reflection. Returns null if Zest is not loaded or the
     * method is missing. Throws if Zest's getChainScript throws (e.g. validation failure); the
     * exception message is then reported to the user.
     *
     * @param scriptWrappers validated chain in order
     * @param runName name for the run
     * @return chain script to invoke, or null
     * @throws Exception when Zest's getChainScript throws (cause is rethrown)
     */
    private ScriptWrapper getChainScriptViaReflection(
            List<ScriptWrapper> scriptWrappers, String runName) throws Exception {
        Object extZest =
                Control.getSingleton().getExtensionLoader().getExtension(EXTENSION_ZEST_NAME);
        if (extZest == null) {
            LOGGER.warn("ExtensionZest not loaded, cannot get chain script");
            return null;
        }
        try {
            Method getChainScript =
                    extZest.getClass().getMethod("getChainScript", List.class, String.class);
            return (ScriptWrapper) getChainScript.invoke(extZest, scriptWrappers, runName);
        } catch (NoSuchMethodException | IllegalAccessException | SecurityException e) {
            LOGGER.warn("Failed to get chain script via ExtensionZest", e);
            return null;
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw new RuntimeException(cause);
        }
    }

    /**
     * Validates chain scripts and returns their wrappers.
     *
     * @param chain script names in order
     * @param jobName for error messages
     * @param progress for error reporting
     * @return validated ScriptWrappers, or null if validation failed
     */
    private List<ScriptWrapper> validateChainScripts(
            List<String> chain, String jobName, AutomationProgress progress) {
        List<ScriptWrapper> scriptWrappers = new ArrayList<>();

        for (String scriptName : chain) {
            ScriptWrapper script = extScript.getScript(scriptName);
            if (script == null) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.chainScriptNotFound",
                                jobName,
                                scriptName));
                return null;
            }

            if (!ExtensionScript.TYPE_STANDALONE.equals(script.getTypeName())
                    || !ZEST_ENGINE_NAME.equals(script.getEngineName())) {
                progress.error(
                        Constant.messages.getString(
                                "scripts.automation.error.chainScriptNotZestStandalone",
                                jobName,
                                scriptName));
                return null;
            }

            scriptWrappers.add(script);
        }

        return scriptWrappers;
    }
}
