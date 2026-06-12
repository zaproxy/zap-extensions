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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder;
import org.zaproxy.zap.extension.scripts.internal.db.ScriptRunRecorder.RunScript;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunDiagnostic;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunRow;
import org.zaproxy.zap.extension.scripts.zest.ZestScriptDiagnosticSource.ZestScriptRunSnapshot;

/** Unit tests for {@link ScriptRunSession}. */
class ScriptRunSessionUnitTest {

    private ExtensionScript extScript;
    private ScriptRunSession session;

    @BeforeEach
    void setUp() {
        extScript = mock(ExtensionScript.class);
        session = new ScriptRunSession(extScript, new AutomationProgress());
    }

    @Test
    void shouldBuildRecordFromZestSnapshotAndAncillaryOutput() {
        ScriptWrapper httpSender = mock(ScriptWrapper.class);
        given(httpSender.getName()).willReturn("http-sender");
        given(httpSender.getTypeName()).willReturn(ExtensionScript.TYPE_HTTP_SENDER);
        given(extScript.getScript("http-sender")).willReturn(httpSender);

        ScriptWrapper primary =
                new ZestScriptWrapper(
                        "standalone",
                        new ZestScriptRunSnapshot(
                                List.of(
                                        new ZestScriptRunRow(
                                                1,
                                                "standalone",
                                                List.of("zest-line"),
                                                Optional.empty()))));

        session.outputCapture().output(primary, "ignored\n");
        session.outputCapture().output(httpSender, "sender-line\n");
        session.flush();

        List<RunScript> rows = session.buildRecord(primary);

        assertThat(rows, hasSize(2));
        assertThat(rows.get(0).scriptName(), is("standalone"));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).message(), is("zest-line"));
        assertThat(rows.get(1).scriptName(), is("http-sender"));
        assertThat(rows.get(1).steps().get(0).outputs().get(0).message(), is("sender-line"));
    }

    @Test
    void shouldBuildNonZestRecordFromOutputCapture() {
        ScriptWrapper script = mock(ScriptWrapper.class);
        given(script.getName()).willReturn("myScript");
        given(script.getTypeName()).willReturn(ExtensionScript.TYPE_STANDALONE);

        session.outputCapture().output(script, "hello\n");
        session.flush();

        List<RunScript> rows = session.buildRecord(script);

        assertThat(rows, hasSize(1));
        assertThat(rows.get(0).scriptName(), is("myScript"));
        assertThat(
                rows.get(0).steps().get(0).outputs().get(0).kind(),
                is(ScriptRunRecorder.OUTPUT_KIND_OUTPUT));
        assertThat(rows.get(0).steps().get(0).outputs().get(0).message(), is("hello"));
    }

    private static final class ZestScriptWrapper extends ScriptWrapper
            implements ZestScriptDiagnosticSource {

        private final ZestScriptRunSnapshot snapshot;

        ZestScriptWrapper(String name, ZestScriptRunSnapshot snapshot) {
            setName(name);
            this.snapshot = snapshot;
        }

        @Override
        public java.util.Optional<ZestScriptRunDiagnostic> getLastRunDiagnostic() {
            return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<ZestScriptRunSnapshot> getLastRunSnapshot() {
            return java.util.Optional.ofNullable(snapshot);
        }
    }
}
