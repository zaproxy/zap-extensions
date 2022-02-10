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
package org.zaproxy.zap.extension.scripts.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ScriptJobOutputListenerUnitTest {

    String SCRIPT_NAME = "TEST";
    ScriptWrapper script;
    ScriptJobOutputListener listener;
    AutomationProgress progress;

    @BeforeEach
    void setUpEach() {
        progress = new AutomationProgress();
        script = mock(ScriptWrapper.class);
        when(script.getName()).thenReturn(SCRIPT_NAME);
        listener = new ScriptJobOutputListener(progress, SCRIPT_NAME);
    }

    @Test
    void shouldWriteOnFlush() {
        listener.output(script, "Hello");
        assertThat(progress.getInfos().size(), is(0));
        listener.flush();
        assertThat(progress.getInfos().size(), is(1));
        assertThat(progress.getInfos(), contains("Hello"));
    }

    @Test
    void shouldWriteOneLine() {
        listener.output(script, "Hello\n");
        assertThat(progress.getInfos().size(), is(1));
        listener.flush();
        assertThat(progress.getInfos().size(), is(1));
        assertThat(progress.getInfos(), contains("Hello"));
    }

    @Test
    void shouldWriteTwoLine() {
        listener.output(script, "Hello\n");
        listener.output(script, "ZAP");
        listener.output(script, "Proxy\n");
        assertThat(progress.getInfos().size(), is(2));
        assertThat(progress.getInfos(), contains("Hello", "ZAPProxy"));
    }

    @Test
    void shouldWriteEmptyLine() {
        listener.output(script, "Hello\n\nZAP");
        listener.output(script, "Proxy\n");
        assertThat(progress.getInfos().size(), is(3));
        assertThat(progress.getInfos(), contains("Hello", "", "ZAPProxy"));
    }
}
