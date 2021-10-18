/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.LinkedHashMap;
import java.util.Locale;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Session;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.HttpAuthSessionManagementMethodType.HttpAuthSessionManagementMethod;
import org.zaproxy.zap.utils.I18N;

class ContextWrapperUnitTest {

    private Session session;
    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    static void init() throws Exception {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        ExtentionAutomationUnitTest.updateEnv("myEnvVar", "envVarValue");
    }

    @AfterAll
    static void close() throws Exception {
        mockedCmdLine.close();
        ExtentionAutomationUnitTest.updateEnv("myEnvVar", "");
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        session = mock(Session.class);
        Context context = mock(Context.class);
        given(session.getNewContext(any())).willReturn(context);
    }

    @Test
    void shouldInitDataForDefaultCookieSessionManagement() {
        // Given
        Session session = mock(Session.class);
        Context context = new Context(session, 0);
        // When
        ContextWrapper cw = new ContextWrapper(context);
        // Then
        assertThat(
                cw.getData().getSessionManagement().getMethod(),
                is(equalTo(ContextWrapper.SessionManagementData.METHOD_COOKIE)));
        assertThat(cw.getData().getSessionManagement().getScriptEngine(), is(nullValue()));
        assertThat(cw.getData().getSessionManagement().getScript(), is(nullValue()));
    }

    @Test
    void shouldInitDataForHttpSessionManagement() {
        // Given
        Session session = mock(Session.class);
        Context context = new Context(session, 0);
        // When
        context.setSessionManagementMethod(new HttpAuthSessionManagementMethod());
        ContextWrapper cw = new ContextWrapper(context);
        // Then
        assertThat(
                cw.getData().getSessionManagement().getMethod(),
                is(equalTo(ContextWrapper.SessionManagementData.METHOD_HTTP)));
        assertThat(cw.getData().getSessionManagement().getScriptEngine(), is(nullValue()));
        assertThat(cw.getData().getSessionManagement().getScript(), is(nullValue()));
    }

    @Test
    void shouldParseWithNoSessionMgmt() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement(), is(nullValue()));
    }

    @Test
    void shouldParseCookieSessionMgmt() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: cookie\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getSessionManagement());
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getMethod(),
                is(ContextWrapper.SessionManagementData.METHOD_COOKIE));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScript(),
                is(nullValue()));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScriptEngine(),
                is(nullValue()));
    }

    @Test
    void shouldParseHttpSessionMgmt() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: http\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getSessionManagement());
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getMethod(),
                is(ContextWrapper.SessionManagementData.METHOD_HTTP));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScript(),
                is(nullValue()));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScriptEngine(),
                is(nullValue()));
    }

    @Test
    void shouldParseScriptSessionMgmt() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: script\n"
                        + "        script: example_script\n"
                        + "        scriptEngine: example_engine\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getSessionManagement());
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getMethod(),
                is(ContextWrapper.SessionManagementData.METHOD_SCRIPT));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScript(),
                is("example_script"));
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getScriptEngine(),
                is("example_engine"));
    }

    @Test
    void shouldErrorOnBadSessionMgmt() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: bad\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.env.sessionmgmt.type.bad!")));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getSessionManagement());
        assertThat(
                env.getContextWrappers().get(0).getData().getSessionManagement().getMethod(),
                is("bad"));
    }
}
