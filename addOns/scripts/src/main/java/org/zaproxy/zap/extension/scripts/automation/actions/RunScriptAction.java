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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import org.zaproxy.zap.extension.scripts.automation.ScriptRunFailureDetail;
import org.zaproxy.zap.extension.scripts.automation.ui.ScriptJobDialog;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.CapturedOutput;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptPrintCapture;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunDiagnostic;
import org.zaproxy.zap.users.User;

public class RunScriptAction extends ScriptAction {

    private static final Logger LOGGER = LogManager.getLogger(RunScriptAction.class);

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
        List<String> chain = parameters.getChain();
        if (chain != null && !chain.isEmpty()) {
            return Constant.messages.getString(
                    "scripts.automation.dialog.summary.run", String.join(", ", chain));
        }
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
                        (e, l) -> reportScriptError(progress, jobName, parameters, script, e, l),
                        l -> persistSingleScriptSuccess(jobName, script, l));
            } else {
                setUserOnZestWrapper(script, user);
                executeScriptWithOutputListener(
                        script,
                        progress,
                        () -> extScript.invokeScript(script),
                        (e, l) -> reportScriptError(progress, jobName, parameters, script, e, l),
                        l -> persistSingleScriptSuccess(jobName, script, l));
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
                (e, l) ->
                        reportChainExecutionError(
                                progress, jobName, chainScript, scriptWrappers, e),
                l -> persistChainSuccess(jobName, chainScript, scriptWrappers))) {
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
     * @param onSuccess hook invoked when the script finished without an exception (e.g. to persist
     *     captured output for diagnostics)
     * @return true if execution succeeded, false otherwise
     */
    private boolean executeScriptWithOutputListener(
            ScriptWrapper script,
            AutomationProgress progress,
            ScriptExecutor executor,
            BiConsumer<Exception, ScriptJobOutputListener> errorHandler,
            Consumer<ScriptJobOutputListener> onSuccess) {
        ScriptJobOutputListener scriptJobOutputListener =
                new ScriptJobOutputListener(progress, script.getName());
        try {
            extScript.addScriptOutputListener(scriptJobOutputListener);
            executor.execute();
            scriptJobOutputListener.flush();

            if (script.getLastException() != null) {
                errorHandler.accept(script.getLastException(), scriptJobOutputListener);
                return false;
            }
            onSuccess.accept(scriptJobOutputListener);
            return true;
        } catch (Exception e) {
            LOGGER.debug("Script execution failed, reported via automation progress", e);
            scriptJobOutputListener.flush();
            errorHandler.accept(e, scriptJobOutputListener);
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
            ScriptWrapper script,
            Exception e,
            ScriptJobOutputListener listener) {
        RunFailure failure = resolveRunFailure(script, e);
        List<CapturedOutput> captured = capturedOutputsForScript(script, listener);
        reportAndPersistFailure(
                progress,
                Constant.messages.getString(
                        "scripts.automation.error.scriptError",
                        jobName,
                        parameters.getName(),
                        failure.progressDetail()),
                Constant.messages.getString(
                        "scripts.automation.persist.failedSummary.single",
                        jobName,
                        parameters.getName()),
                List.of(
                        new ScriptRunRecorder.RunScript(
                                StringUtils.defaultString(parameters.getName()),
                                StringUtils.defaultString(script.getTypeName()),
                                captured,
                                failure.failureStep())),
                failure);
    }

    private void reportChainExecutionError(
            AutomationProgress progress,
            String jobName,
            ScriptWrapper chainScript,
            List<ScriptWrapper> chainMembers,
            Exception e) {
        String chainOrder = String.join(" -> ", parameters.getChain());
        RunFailure failure = resolveRunFailure(chainScript, e);
        Map<Integer, List<CapturedOutput>> byOrder =
                bucketCapturesByChainOrder(chainScript, chainMembers.size());
        reportAndPersistFailure(
                progress,
                Constant.messages.getString(
                        "scripts.automation.error.chainExecutionFailed",
                        jobName,
                        chainOrder,
                        failure.progressDetail()),
                Constant.messages.getString(
                        "scripts.automation.persist.failedSummary.chain", jobName, chainOrder),
                toRunScripts(chainMembers, byOrder, failure),
                failure);
    }

    private static void reportAndPersistFailure(
            AutomationProgress progress,
            String progressMessage,
            String persistSummary,
            List<ScriptRunRecorder.RunScript> scripts,
            RunFailure failure) {
        progress.error(progressMessage);
        ScriptRunRecorder.recordFailedRun(persistSummary, scripts, failure.outputDetail());
    }

    /** Skips silent successes; {@link ScriptRunRecorder} only writes what it is given. */
    private static void persistSingleScriptSuccess(
            String jobName, ScriptWrapper script, ScriptJobOutputListener listener) {
        List<CapturedOutput> outputs = capturedOutputsForScript(script, listener);
        if (outputs.isEmpty()) {
            return;
        }
        ScriptRunRecorder.recordRun(
                Constant.messages.getString(
                        "scripts.automation.persist.successSummary.single",
                        jobName,
                        StringUtils.defaultString(script.getName())),
                ScriptRunRecorder.OUTCOME_SUCCESS,
                List.of(
                        new ScriptRunRecorder.RunScript(
                                StringUtils.defaultString(script.getName()),
                                StringUtils.defaultString(script.getTypeName()),
                                outputs,
                                null)),
                null);
    }

    private void persistChainSuccess(
            String jobName, ScriptWrapper chainScript, List<ScriptWrapper> chainMembers) {
        Map<Integer, List<CapturedOutput>> byOrder =
                bucketCapturesByChainOrder(chainScript, chainMembers.size());
        if (byOrder.isEmpty()) {
            return;
        }
        String chainOrderLabel = String.join(" -> ", parameters.getChain());
        List<ScriptRunRecorder.RunScript> rows = new ArrayList<>(chainMembers.size());
        for (int i = 0; i < chainMembers.size(); i++) {
            ScriptWrapper m = chainMembers.get(i);
            rows.add(
                    new ScriptRunRecorder.RunScript(
                            StringUtils.defaultString(m.getName()),
                            StringUtils.defaultString(m.getTypeName()),
                            byOrder.getOrDefault(i + 1, List.of()),
                            null));
        }
        ScriptRunRecorder.recordRun(
                Constant.messages.getString(
                        "scripts.automation.persist.successSummary.chain",
                        jobName,
                        chainOrderLabel),
                ScriptRunRecorder.OUTCOME_SUCCESS,
                rows,
                null);
    }

    private static List<CapturedOutput> linesToCapturedOutputs(List<String> lines) {
        return lines.stream().map(CapturedOutput::new).toList();
    }

    /**
     * Listener lines (e.g. JS {@code print}) plus Zest {@code ZestActionPrint} captures from the
     * last standalone run ({@code chainScriptOrder == -1}).
     */
    private static List<CapturedOutput> capturedOutputsForScript(
            ScriptWrapper script, ScriptJobOutputListener listener) {
        List<CapturedOutput> outputs =
                new ArrayList<>(linesToCapturedOutputs(listener.getCapturedLines()));
        if (!(script instanceof ZestScriptDiagnosticSource source)) {
            return outputs;
        }
        for (ZestScriptPrintCapture capture : source.getLastRunPrintCaptures()) {
            if (capture.chainScriptOrder() != -1) {
                continue;
            }
            String message = StringUtils.defaultString(capture.line());
            if (outputs.stream().anyMatch(o -> message.equals(o.message()))) {
                continue;
            }
            outputs.add(new CapturedOutput(message));
        }
        return outputs;
    }

    private static Map<Integer, List<CapturedOutput>> bucketCapturesByChainOrder(
            ScriptWrapper chainScript, int memberCount) {
        Map<Integer, List<CapturedOutput>> bucketed = new HashMap<>();
        if (!(chainScript instanceof ZestScriptDiagnosticSource source)) {
            return bucketed;
        }
        for (ZestScriptPrintCapture c : source.getLastRunPrintCaptures()) {
            int order = c.chainScriptOrder();
            if (order < 1 || order > memberCount) {
                continue;
            }
            bucketed.computeIfAbsent(order, k -> new ArrayList<>())
                    .add(new CapturedOutput(StringUtils.defaultString(c.line())));
        }
        return bucketed;
    }

    private static List<ScriptRunRecorder.RunScript> toRunScripts(
            List<ScriptWrapper> chainMembers,
            Map<Integer, List<CapturedOutput>> capturesByOrder,
            RunFailure failure) {
        int failingOrder = failure.failingScriptOrder();
        List<ScriptRunRecorder.RunScript> scripts = new ArrayList<>(chainMembers.size());
        for (int i = 0; i < chainMembers.size(); i++) {
            int order = i + 1;
            ScriptWrapper w = chainMembers.get(i);
            ScriptRunRecorder.FailureStep step = null;
            if (order == failingOrder || (failingOrder < 1 && order == 1)) {
                step = failure.failureStep();
            }
            scripts.add(
                    new ScriptRunRecorder.RunScript(
                            StringUtils.defaultString(w.getName()),
                            StringUtils.defaultString(w.getTypeName()),
                            capturesByOrder.getOrDefault(order, List.of()),
                            step));
        }
        return scripts;
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

    record RunFailure(
            String progressDetail,
            String outputDetail,
            int failingScriptOrder,
            ScriptRunRecorder.FailureStep failureStep) {}

    static RunFailure resolveRunFailure(ScriptWrapper script, Exception e) {
        Optional<ZestScriptRunDiagnostic> diagnostic = zestDiagnostic(script);
        String zestCtx = diagnostic.map(ZestScriptRunDiagnostic::context).orElse("");
        String progressDetail = zestCtx.isEmpty() ? exceptionSummary(e) : zestCtx;
        String outputDetail = diagnostic.map(ZestScriptRunDiagnostic::detailMessage).orElse("");
        if (StringUtils.isBlank(outputDetail)) {
            outputDetail = ScriptRunFailureDetail.compactExceptionDetailForPersistence(e);
        }
        int failingScriptOrder =
                diagnostic.map(ZestScriptRunDiagnostic::chainScriptOrder).orElse(-1);
        return new RunFailure(
                progressDetail, outputDetail, failingScriptOrder, failureStepFrom(diagnostic));
    }

    private static Optional<ZestScriptRunDiagnostic> zestDiagnostic(ScriptWrapper script) {
        if (script instanceof ZestScriptDiagnosticSource source) {
            return source.getLastRunDiagnostic();
        }
        return Optional.empty();
    }

    private static ScriptRunRecorder.FailureStep failureStepFrom(
            Optional<ZestScriptRunDiagnostic> diagnostic) {
        return diagnostic
                .map(
                        d ->
                                new ScriptRunRecorder.FailureStep(
                                        d.sourceStatementIndex(),
                                        StringUtils.defaultString(d.elementType())))
                .orElse(new ScriptRunRecorder.FailureStep(-1, ""));
    }

    private static String exceptionSummary(Exception e) {
        String message = e.getMessage();
        return message != null ? message : e.getClass().getName();
    }
}
