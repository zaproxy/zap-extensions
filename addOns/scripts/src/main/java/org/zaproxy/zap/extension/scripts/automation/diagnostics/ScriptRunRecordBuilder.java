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
package org.zaproxy.zap.extension.scripts.automation.diagnostics;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.scripts.automation.ScriptRunFailureDetail;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunFailureDiagnostic;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunOutput;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;

/** Builds {@link ScriptRunRecorder.RunScript} rows for persistence. */
public final class ScriptRunRecordBuilder {

    private static final Logger LOGGER = LogManager.getLogger(ScriptRunRecordBuilder.class);

    private ScriptRunRecordBuilder() {}

    public record ScriptMember(String scriptName, String scriptType) {}

    public record RunFailure(
            String progressDetail,
            String outputDetail,
            int failingScriptOrder,
            ScriptRunRecorder.FailureStep failureStep) {}

    public static List<ScriptRunRecorder.RunScript> build(
            List<ScriptMember> members,
            RunFailure failure,
            List<RunOutput> runOutputs,
            String failureOutputDetail) {
        Map<String, List<RunOutput>> outputsByScript = groupOutputsByScript(runOutputs);
        attachUnmatchedOutputsToFirstMember(outputsByScript, members);
        int failingOrder = failure != null ? failure.failingScriptOrder() : -1;
        List<ScriptRunRecorder.RunScript> scripts = new ArrayList<>(members.size());
        for (int i = 0; i < members.size(); i++) {
            int order = i + 1;
            ScriptMember member = members.get(i);
            ScriptRunRecorder.FailureStep scriptFailure = null;
            // Unknown chain order (< 1) from non-Zest engines or missing chain provenance: attach
            // the failure step to the first member so ERROR has a persistence row. Single-script
            // runs rely on this; for multi-script chains the script name may not match the segment.
            if (failure != null && (order == failingOrder || (failingOrder < 1 && order == 1))) {
                scriptFailure = failure.failureStep();
            }
            scripts.add(
                    new ScriptRunRecorder.RunScript(
                            member.scriptName(),
                            member.scriptType(),
                            buildSteps(
                                    outputsByScript.getOrDefault(member.scriptName(), List.of()),
                                    scriptFailure,
                                    failureOutputDetail)));
        }
        return scripts;
    }

    private static Map<String, List<RunOutput>> groupOutputsByScript(List<RunOutput> runOutputs) {
        Map<String, List<RunOutput>> grouped = new HashMap<>();
        for (RunOutput output : runOutputs) {
            grouped.computeIfAbsent(output.scriptName(), k -> new ArrayList<>()).add(output);
        }
        return grouped;
    }

    private static void attachUnmatchedOutputsToFirstMember(
            Map<String, List<RunOutput>> outputsByScript, List<ScriptMember> members) {
        if (members.isEmpty()) {
            return;
        }
        Set<String> memberNames = new HashSet<>();
        for (ScriptMember member : members) {
            memberNames.add(member.scriptName());
        }
        List<RunOutput> unmatched = new ArrayList<>();
        outputsByScript
                .entrySet()
                .removeIf(
                        entry -> {
                            if (memberNames.contains(entry.getKey())) {
                                return false;
                            }
                            unmatched.addAll(entry.getValue());
                            return true;
                        });
        if (unmatched.isEmpty()) {
            return;
        }
        String firstMemberName = members.get(0).scriptName();
        LOGGER.warn(
                "Attributing {} unmatched script stdout line(s) to first chain member: {}",
                unmatched.size(),
                firstMemberName);
        outputsByScript.computeIfAbsent(firstMemberName, k -> new ArrayList<>()).addAll(unmatched);
    }

    private static List<ScriptRunRecorder.RunStep> buildSteps(
            List<RunOutput> stdoutLines,
            ScriptRunRecorder.FailureStep failure,
            String failureOutputDetail) {
        Map<Integer, StepAccumulator> byIndex = new HashMap<>();
        for (RunOutput line : stdoutLines) {
            byIndex.computeIfAbsent(line.sourceStatementIndex(), StepAccumulator::new)
                    .addStdout(line);
        }
        if (failure != null) {
            byIndex.computeIfAbsent(failure.sourceStepIndex(), StepAccumulator::new)
                    .applyFailure(failure, failureOutputDetail);
        }
        if (byIndex.isEmpty()) {
            return List.of();
        }
        return byIndex.values().stream()
                .sorted(Comparator.comparingInt(StepAccumulator::sortKey))
                .map(StepAccumulator::toRunStep)
                .toList();
    }

    public static RunFailure resolveFailure(
            org.zaproxy.zap.extension.script.ScriptWrapper script, Exception e) {
        if (script instanceof ScriptDiagnosticSource source) {
            Optional<RunFailureDiagnostic> diagnostic = source.getRunDiagnostics().failure();
            if (diagnostic.isPresent()) {
                RunFailureDiagnostic d = diagnostic.get();
                String outputDetail = d.detailMessage();
                if (StringUtils.isBlank(outputDetail)) {
                    outputDetail = ScriptRunFailureDetail.compactExceptionDetailForPersistence(e);
                }
                return new RunFailure(
                        d.context(),
                        outputDetail,
                        d.chainScriptOrder(),
                        new ScriptRunRecorder.FailureStep(
                                d.sourceStatementIndex(), d.elementType(), d.screenshotBase64()));
            }
        }
        String summary = exceptionSummary(e);
        return new RunFailure(
                summary,
                ScriptRunFailureDetail.compactExceptionDetailForPersistence(e),
                -1,
                new ScriptRunRecorder.FailureStep(-1, ""));
    }

    private static String exceptionSummary(Exception e) {
        String message = e.getMessage();
        return message != null ? message : e.getClass().getName();
    }

    private static final class StepAccumulator {
        private final int sourceStepIndex;
        private int minOrdinal = Integer.MAX_VALUE;
        private String line = "";
        private String screenshotBase64;
        private String errorMessage;
        private final List<ScriptRunRecorder.StepOutput> stdoutOutputs = new ArrayList<>();

        private StepAccumulator(int sourceStepIndex) {
            this.sourceStepIndex = sourceStepIndex;
        }

        private void addStdout(RunOutput output) {
            minOrdinal = Math.min(minOrdinal, output.ordinal());
            if (line.isEmpty() && StringUtils.isNotBlank(output.elementType())) {
                line = output.elementType();
            }
            stdoutOutputs.add(
                    new ScriptRunRecorder.StepOutput(
                            output.ordinal(),
                            ScriptRunRecorder.OUTPUT_KIND_OUTPUT,
                            output.message()));
        }

        private void applyFailure(
                ScriptRunRecorder.FailureStep failure, String failureOutputDetail) {
            if (StringUtils.isNotBlank(failure.line())) {
                line = failure.line();
            }
            screenshotBase64 = failure.screenshotBase64();
            errorMessage = failureOutputDetail;
        }

        private int sortKey() {
            return minOrdinal == Integer.MAX_VALUE ? Integer.MAX_VALUE : minOrdinal;
        }

        private ScriptRunRecorder.RunStep toRunStep() {
            List<ScriptRunRecorder.StepOutput> outputs = new ArrayList<>(stdoutOutputs);
            if (errorMessage != null) {
                int errorOrdinal =
                        stdoutOutputs.stream()
                                        .mapToInt(ScriptRunRecorder.StepOutput::ordinal)
                                        .max()
                                        .orElse(-1)
                                + 1;
                outputs.add(
                        new ScriptRunRecorder.StepOutput(
                                errorOrdinal, ScriptRunRecorder.OUTPUT_KIND_ERROR, errorMessage));
            }
            return new ScriptRunRecorder.RunStep(sourceStepIndex, line, outputs, screenshotBase64);
        }
    }
}
