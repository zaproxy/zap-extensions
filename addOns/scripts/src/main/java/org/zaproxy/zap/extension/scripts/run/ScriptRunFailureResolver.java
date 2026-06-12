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
package org.zaproxy.zap.extension.scripts.run;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptRunFailureDetail;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunStep;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunDiagnostic;

/** Resolves failure details for script run persistence. */
public final class ScriptRunFailureResolver {

    public record RunFailure(
            String progressDetail,
            String outputDetail,
            int failingScriptOrder,
            int sourceStepIndex,
            String elementType,
            String screenshotBase64) {}

    private ScriptRunFailureResolver() {}

    public static RunFailure resolve(ScriptWrapper script, Exception e) {
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
                progressDetail,
                outputDetail,
                failingScriptOrder,
                diagnostic.map(ZestScriptRunDiagnostic::sourceStatementIndex).orElse(-1),
                diagnostic.map(d -> StringUtils.defaultString(d.elementType())).orElse(""),
                diagnostic.map(ZestScriptRunDiagnostic::screenshotBase64).orElse(null));
    }

    public static List<RunScript> buildFailedScriptRun(ScriptWrapper script) {
        String screenshotBase64 = null;
        if (script instanceof ZestScriptDiagnosticSource source) {
            screenshotBase64 =
                    source.getLastRunDiagnostic()
                            .map(ZestScriptRunDiagnostic::screenshotBase64)
                            .orElse(null);
        }
        List<RunStep> steps =
                List.of(
                        ScriptRunOutputCapture.errorStep(
                                -1,
                                "",
                                StringUtils.defaultString(
                                        ScriptRunFailureDetail
                                                .compactScriptOutputDetailForPersistence(script)),
                                screenshotBase64));
        return List.of(
                new RunScript(
                        script.getName(), StringUtils.defaultString(script.getTypeName()), steps));
    }

    public static List<RunScript> addNonZestFailure(
            List<RunScript> scripts, ScriptWrapper primary, Exception e) {
        RunFailure failure = resolve(primary, e);
        if (primary instanceof ZestScriptDiagnosticSource) {
            return scripts;
        }
        List<RunScript> result = new ArrayList<>(scripts);
        String primaryName = StringUtils.defaultString(primary.getName());
        boolean updated = false;
        for (int i = 0; i < result.size(); i++) {
            RunScript row = result.get(i);
            if (primaryName.equals(row.scriptName())) {
                List<RunStep> steps = new ArrayList<>(row.steps());
                steps.add(
                        ScriptRunOutputCapture.errorStep(
                                failure.sourceStepIndex(),
                                failure.elementType(),
                                failure.outputDetail(),
                                failure.screenshotBase64()));
                result.set(i, new RunScript(row.scriptName(), row.scriptType(), steps));
                updated = true;
                break;
            }
        }
        if (!updated) {
            result.add(
                    new RunScript(
                            primaryName,
                            StringUtils.defaultString(primary.getTypeName()),
                            List.of(
                                    ScriptRunOutputCapture.errorStep(
                                            failure.sourceStepIndex(),
                                            failure.elementType(),
                                            failure.outputDetail(),
                                            failure.screenshotBase64()))));
        }
        return result;
    }

    private static Optional<ZestScriptRunDiagnostic> zestDiagnostic(ScriptWrapper script) {
        if (script instanceof ZestScriptDiagnosticSource source) {
            return source.getLastRunDiagnostic();
        }
        return Optional.empty();
    }

    private static String exceptionSummary(Exception e) {
        String message = e.getMessage();
        return message != null ? message : e.getClass().getName();
    }
}
