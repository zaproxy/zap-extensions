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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Locale;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link AddScriptAction}. */
class AddScriptActionUnitTest extends TestUtils {

    private static final String JOB_NAME = "Job Name";

    private ExtensionScript extension;

    private AutomationPlan plan;
    private AutomationEnvironment env;
    private AutomationProgress progress;
    private ScriptJobParameters parameters;

    private AddScriptAction action;

    @BeforeAll
    static void setupAll() {
        Constant.messages = new I18N(Locale.ROOT);
    }

    @BeforeEach
    void setup() {
        extension = mock(ExtensionScript.class);
        ExtensionLoader extensionLoader = mock();
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extension);
        Control.initSingletonForTesting(mock(Model.class), extensionLoader);

        plan = new AutomationPlan();
        env = plan.getEnv();
        progress = mock(AutomationProgress.class);
        parameters =
                new ScriptJobParameters(AddScriptAction.NAME, null, null, "", "", "", "", "", "");

        action = new AddScriptAction(parameters);
    }

    @Test
    void shouldCreateInlinedScriptIfSourceIsEmpty() {
        // Given
        parameters.setInline("inline content");
        // When
        action.runJob(JOB_NAME, env, progress);
        // Then
        ArgumentCaptor<ScriptWrapper> argCaptor = ArgumentCaptor.forClass(ScriptWrapper.class);
        verify(extension).addScript(argCaptor.capture(), eq(false));
        ScriptWrapper sw = argCaptor.getValue();
        assertThat(sw.getFile(), is(nullValue()));
        assertThat(sw.getContents(), is(equalTo(parameters.getInline())));
    }
}
