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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.scripts.diagnostics.ScriptDiagnosticSource.RunOutput;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;

/** Unit tests for {@link ScriptRunRecordBuilder}. */
class ScriptRunRecordBuilderUnitTest {

    @Test
    void shouldGroupRunOutputsByScriptNameIntoSteps() {
        List<RunOutput> outputs =
                List.of(
                        new RunOutput("script-a", 1, 0, "ZestActionPrint", "first"),
                        new RunOutput("script-b", 2, 1, "ZestActionPrint", "other"),
                        new RunOutput("script-a", 3, 2, "ZestActionPrint", "second"));

        List<ScriptRunRecorder.RunScript> rows =
                ScriptRunRecordBuilder.build(
                        List.of(
                                new ScriptRunRecordBuilder.ScriptMember("script-a", "standalone"),
                                new ScriptRunRecordBuilder.ScriptMember("script-b", "standalone")),
                        null,
                        outputs,
                        "");

        assertThat(rows, hasSize(2));
        assertThat(rows.get(0).steps(), hasSize(2));
        assertThat(rows.get(0).steps().get(0).sourceStepIndex(), is(equalTo(1)));
        assertThat(rows.get(0).steps().get(0).outputs(), hasSize(1));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).kind(), is(equalTo("OUTPUT")));
        assertThat(rows.get(0).steps().get(1).sourceStepIndex(), is(equalTo(3)));
        assertThat(rows.get(1).steps(), hasSize(1));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is(equalTo("other")));
    }

    @Test
    void shouldMergeStdoutAndFailureOnSameStep() {
        List<RunOutput> outputs =
                List.of(new RunOutput("script-a", 5, 0, "ZestActionPrint", "before fail"));
        ScriptRunRecordBuilder.RunFailure failure =
                new ScriptRunRecordBuilder.RunFailure(
                        "ctx",
                        "boom",
                        1,
                        new ScriptRunRecorder.FailureStep(5, "ZestClientClick", "png"));

        List<ScriptRunRecorder.RunScript> rows =
                ScriptRunRecordBuilder.build(
                        List.of(new ScriptRunRecordBuilder.ScriptMember("script-a", "standalone")),
                        failure,
                        outputs,
                        "boom");

        assertThat(rows.get(0).steps(), hasSize(1));
        ScriptRunRecorder.RunStep step = rows.get(0).steps().get(0);
        assertThat(step.sourceStepIndex(), is(equalTo(5)));
        assertThat(step.line(), is(equalTo("ZestClientClick")));
        assertThat(step.outputs(), hasSize(2));
        assertThat(step.outputs().get(0).kind(), is(equalTo("OUTPUT")));
        assertThat(step.outputs().get(1).kind(), is(equalTo("ERROR")));
        assertThat(step.screenshotBase64(), is(equalTo("png")));
    }

    @Test
    void shouldAttachFailureToFirstMemberWhenChainOrderUnknown() {
        ScriptRunRecordBuilder.RunFailure failure =
                new ScriptRunRecordBuilder.RunFailure(
                        "ctx",
                        "boom",
                        -1,
                        new ScriptRunRecorder.FailureStep(5, "ZestClientClick", null));

        List<ScriptRunRecorder.RunScript> rows =
                ScriptRunRecordBuilder.build(
                        List.of(
                                new ScriptRunRecordBuilder.ScriptMember("script-a", "standalone"),
                                new ScriptRunRecordBuilder.ScriptMember("script-b", "standalone"),
                                new ScriptRunRecordBuilder.ScriptMember("script-c", "standalone")),
                        failure,
                        List.of(),
                        "boom");

        assertThat(rows, hasSize(3));
        assertThat(rows.get(0).steps(), hasSize(1));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).kind(), is(equalTo("ERROR")));
        assertThat(rows.get(1).steps(), hasSize(0));
        assertThat(rows.get(2).steps(), hasSize(0));
    }

    @Test
    void shouldAttachUnmatchedStdoutToFirstChainMember() {
        List<RunOutput> outputs =
                List.of(new RunOutput("orphan-script", 2, 0, "ZestActionPrint", "lost line"));

        List<ScriptRunRecorder.RunScript> rows =
                ScriptRunRecordBuilder.build(
                        List.of(
                                new ScriptRunRecordBuilder.ScriptMember("script-a", "standalone"),
                                new ScriptRunRecordBuilder.ScriptMember("script-b", "standalone")),
                        null,
                        outputs,
                        "");

        assertThat(rows.get(0).steps(), hasSize(1));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).message(), is(equalTo("lost line")));
        assertThat(rows.get(1).steps(), hasSize(0));
    }
}
