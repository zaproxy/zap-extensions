/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunStep;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.StepOutput;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptPrintCapture;

/** Builds {@link RunScript} rows from collected listener and Zest diagnostic data. */
public final class ScriptRunRecordAssembler {

    /** Failure metadata for assembling ERROR steps. */
    public record FailureContext(
            String errorMessage,
            int failingScriptOrder,
            int sourceStepIndex,
            String elementType,
            String screenshotBase64) {}

    private final ExtensionScript extScript;

    public ScriptRunRecordAssembler(ExtensionScript extScript) {
        this.extScript = extScript;
    }

    public List<RunScript> assembleSingleScript(
            ScriptWrapper script,
            ScriptJobOutputListener listener,
            Optional<FailureContext> failure) {
        List<RunScript> scripts = new ArrayList<>();
        List<RunStep> steps = new ArrayList<>();
        String scriptName = StringUtils.defaultString(script.getName());

        if (script instanceof ZestScriptDiagnosticSource zest) {
            steps.addAll(outputStepsFromZestPrints(zest.getLastRunPrintCaptures(), -1));
        } else {
            steps.addAll(outputStepsFromListener(listener, scriptName));
        }

        failure.ifPresent(
                f ->
                        steps.add(
                                errorStep(
                                        f.sourceStepIndex(),
                                        f.elementType(),
                                        f.errorMessage(),
                                        f.screenshotBase64())));

        scripts.add(
                new RunScript(scriptName, StringUtils.defaultString(script.getTypeName()), steps));
        scripts.addAll(ancillaryScripts(listener, Set.of(scriptName)));
        return scripts;
    }

    public List<RunScript> assembleChain(
            ScriptWrapper chainScript,
            List<ScriptWrapper> chainMembers,
            ScriptJobOutputListener listener,
            Optional<FailureContext> failure) {
        List<RunScript> scripts = new ArrayList<>(chainMembers.size());
        Set<String> memberNames = new HashSet<>();
        List<ZestScriptPrintCapture> zestPrints =
                chainScript instanceof ZestScriptDiagnosticSource zest
                        ? zest.getLastRunPrintCaptures()
                        : List.of();
        int failingOrder = failure.map(FailureContext::failingScriptOrder).orElse(-1);

        for (int i = 0; i < chainMembers.size(); i++) {
            int order = i + 1;
            ScriptWrapper member = chainMembers.get(i);
            String memberName = StringUtils.defaultString(member.getName());
            memberNames.add(memberName);

            List<RunStep> steps = new ArrayList<>();
            steps.addAll(outputStepsFromZestPrints(zestPrints, order));
            steps.addAll(outputStepsFromListener(listener, memberName));

            if (failure.isPresent() && isFailingMember(order, failingOrder)) {
                FailureContext f = failure.get();
                steps.add(
                        errorStep(
                                f.sourceStepIndex(),
                                f.elementType(),
                                f.errorMessage(),
                                f.screenshotBase64()));
            }

            scripts.add(
                    new RunScript(
                            memberName, StringUtils.defaultString(member.getTypeName()), steps));
        }

        Set<String> nonAncillaryNames = new HashSet<>(memberNames);
        // Zest ActionPrint is attributed via printCaptures; the same lines also reach the listener
        // under the merged chain wrapper name and must not become a separate script row.
        nonAncillaryNames.add(StringUtils.defaultString(chainScript.getName()));
        scripts.addAll(ancillaryScripts(listener, nonAncillaryNames));
        return scripts;
    }

    private static boolean isFailingMember(int order, int failingOrder) {
        return order == failingOrder || (failingOrder < 1 && order == 1);
    }

    private List<RunScript> ancillaryScripts(
            ScriptJobOutputListener listener, Set<String> primaryScriptNames) {
        List<RunScript> ancillary = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry :
                listener.getCapturedLinesByScriptName().entrySet()) {
            if (primaryScriptNames.contains(entry.getKey()) || entry.getValue().isEmpty()) {
                continue;
            }
            List<RunStep> steps = outputStepsFromListener(listener, entry.getKey());
            if (steps.isEmpty()) {
                continue;
            }
            ScriptWrapper wrapper = extScript.getScript(entry.getKey());
            String scriptType =
                    wrapper != null ? StringUtils.defaultString(wrapper.getTypeName()) : "";
            ancillary.add(new RunScript(entry.getKey(), scriptType, steps));
        }
        return ancillary;
    }

    private static List<RunStep> outputStepsFromZestPrints(
            List<ZestScriptPrintCapture> captures, int chainScriptOrder) {
        List<RunStep> steps = new ArrayList<>();
        for (ZestScriptPrintCapture capture : captures) {
            if (capture.chainScriptOrder() != chainScriptOrder) {
                continue;
            }
            steps.add(outputStep(StringUtils.defaultString(capture.line())));
        }
        return steps;
    }

    private static List<RunStep> outputStepsFromListener(
            ScriptJobOutputListener listener, String scriptName) {
        List<RunStep> steps = new ArrayList<>();
        List<String> lines =
                listener.getCapturedLinesByScriptName().getOrDefault(scriptName, List.of());
        for (String line : lines) {
            steps.add(outputStep(line));
        }
        return steps;
    }

    private static RunStep outputStep(String message) {
        return new RunStep(
                -1,
                "",
                List.of(
                        new StepOutput(
                                ScriptRunRecorder.OUTPUT_KIND_OUTPUT,
                                StringUtils.defaultString(message))),
                null);
    }

    private static RunStep errorStep(
            int sourceStepIndex, String line, String message, String screenshotBase64) {
        return new RunStep(
                sourceStepIndex,
                StringUtils.defaultString(line),
                List.of(
                        new StepOutput(
                                ScriptRunRecorder.OUTPUT_KIND_ERROR,
                                StringUtils.defaultString(message))),
                screenshotBase64);
    }
}
