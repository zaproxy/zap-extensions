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

import java.io.File;
import java.io.IOException;
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
import org.zaproxy.addon.automation.ContextWrapper.UserData;
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
                is(equalTo(SessionManagementData.METHOD_COOKIE)));
        assertThat(
                cw.getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT),
                is(nullValue()));
        assertThat(
                cw.getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
                is(nullValue()));
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
                is(equalTo(SessionManagementData.METHOD_HTTP)));
        assertThat(
                cw.getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT),
                is(nullValue()));
        assertThat(
                cw.getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
                is(nullValue()));
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
                is(SessionManagementData.METHOD_COOKIE));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT),
                is(nullValue()));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
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
                is(SessionManagementData.METHOD_HTTP));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT),
                is(nullValue()));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
                is(nullValue()));
    }

    @Test
    void shouldParseScriptSessionMgmtInOldFormat() throws IOException {
        // Given
        File f = File.createTempFile("sessmgmt-oldformat", ".js");
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: script\n"
                        + "        script: "
                        + f.getAbsolutePath()
                        + "\n"
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
                is(SessionManagementData.METHOD_SCRIPT));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT)
                        .contains("/sessmgmt-oldformat"),
                is(true));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
                is("example_engine"));
    }

    @Test
    void shouldParseScriptSessionMgmtInNewFormat() throws IOException {
        // Given
        File f = File.createTempFile("sessmgmt-newformat", ".js");
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: script\n"
                        + "        parameters:\n"
                        + "          script: "
                        + f.getAbsolutePath()
                        + "\n"
                        + "          scriptEngine: example_engine\n"
                        + "          param: value\n";
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
                is(SessionManagementData.METHOD_SCRIPT));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT)
                        .contains("/sessmgmt-newformat"),
                is(true));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get(SessionManagementData.PARAM_SCRIPT_ENGINE),
                is("example_engine"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getSessionManagement()
                        .getParameters()
                        .get("param"),
                is("value"));
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

    @Test
    void shouldFailOnSessionMgmtNoScript() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      sessionManagement:\n"
                        + "        method: script\n"
                        + "        parameters:\n"
                        + "          scriptEngine: example_engine\n"
                        + "          param: value\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.env.sessionmgmt.script.missing!")));
    }

    @Test
    void shouldErrorOnBadUsers() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      users: 'Freda'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.context.baduserslist!")));
    }

    @Test
    void shouldHandleEmptyUsers() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      users:";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldLoadValidUsersInOldFormat() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      users:\n"
                        + "      - name: 'Freda'\n"
                        + "        username: 'freda@example.com'\n"
                        + "        password: 'freda123'\n"
                        + "      - name: 'Fred'\n"
                        + "        username: 'fred@example.com'\n"
                        + "        password: 'fred456'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getUsers());
        assertThat(env.getContextWrappers().get(0).getData().getUsers().size(), is(2));
        assertThat(
                env.getContextWrappers().get(0).getData().getUsers().get(0).getName(), is("Freda"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(0)
                        .getCredential(UserData.USERNAME_CREDENTIAL),
                is("freda@example.com"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(0)
                        .getCredential(UserData.PASSWORD_CREDENTIAL),
                is("freda123"));
        assertThat(
                env.getContextWrappers().get(0).getData().getUsers().get(1).getName(), is("Fred"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(1)
                        .getCredential(UserData.USERNAME_CREDENTIAL),
                is("fred@example.com"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(1)
                        .getCredential(UserData.PASSWORD_CREDENTIAL),
                is("fred456"));
    }

    @Test
    void shouldLoadValidUsersInNewFormat() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      users:\n"
                        + "      - name: 'Freda'\n"
                        + "        username: 'freda@example.com'\n"
                        + "        password: 'freda123'\n"
                        + "      - name: 'Fred'\n"
                        + "        credentials:\n"
                        + "          username: 'fred@example.com'\n"
                        + "          password: 'fred456'\n"
                        + "          key: '123456'\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getUsers());
        assertThat(env.getContextWrappers().get(0).getData().getUsers().size(), is(2));
        assertThat(
                env.getContextWrappers().get(0).getData().getUsers().get(0).getName(), is("Freda"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(0)
                        .getCredential(UserData.USERNAME_CREDENTIAL),
                is("freda@example.com"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(0)
                        .getCredential(UserData.PASSWORD_CREDENTIAL),
                is("freda123"));
        assertThat(
                env.getContextWrappers().get(0).getData().getUsers().get(1).getName(), is("Fred"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(1)
                        .getCredential(UserData.USERNAME_CREDENTIAL),
                is("fred@example.com"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getUsers()
                        .get(1)
                        .getCredential(UserData.PASSWORD_CREDENTIAL),
                is("fred456"));
        assertThat(
                env.getContextWrappers().get(0).getData().getUsers().get(1).getCredential("key"),
                is("123456"));
    }

    @Test
    void shouldErrorOnBadAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication: 'None'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.env.badauth!")));
    }

    @Test
    void shouldErrorOnBadAuthMethod() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'Bad'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!automation.error.env.auth.type.bad!")));
    }

    @Test
    void shouldWarnOnBadAuthKey() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'manual'\n"
                        + "        abc: xyz";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo(("!automation.error.options.unknown!"))));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertThat(
                env.getContextWrappers().get(0).getData().getAuthentication().getMethod(),
                is(AuthenticationData.METHOD_MANUAL));
    }

    @Test
    void shouldHandleEmptyAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldLoadManualAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'manual'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertThat(
                env.getContextWrappers().get(0).getData().getAuthentication().getMethod(),
                is(AuthenticationData.METHOD_MANUAL));
    }

    @Test
    void shouldLoadHttpAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'http'\n"
                        + "        parameters:\n"
                        + "          hostname: https://www.example.com\n"
                        + "          realm: test\n"
                        + "          port: 8080";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertThat(
                env.getContextWrappers().get(0).getData().getAuthentication().getMethod(),
                is(AuthenticationData.METHOD_HTTP));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .size(),
                is(3));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_HOSTNAME),
                is("https://www.example.com"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_REALM),
                is("test"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_PORT),
                is(8080));
    }

    @Test
    void shouldLoadFormAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'form'\n"
                        + "        parameters:\n"
                        + "          loginPageUrl: https://www.example.com/login1\n"
                        + "          loginRequestUrl: https://www.example.com/login1\n"
                        + "          loginRequestBody: 'username={%username%}&password={%password%}'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertThat(
                env.getContextWrappers().get(0).getData().getAuthentication().getMethod(),
                is(AuthenticationData.METHOD_FORM));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .size(),
                is(3));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_PAGE_URL),
                is("https://www.example.com/login1"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_REQUEST_URL),
                is("https://www.example.com/login1"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is("username={%username%}&password={%password%}"));
    }

    @Test
    void shouldLoadJsonAuth() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        method: 'json'\n"
                        + "        parameters:\n"
                        + "          loginPageUrl: https://www.example.com/login1\n"
                        + "          loginRequestUrl: https://www.example.com/login1\n"
                        + "          loginRequestBody: '{\"email\":\"{%username%}\",\"password\":\"{%password%}\"}'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertThat(
                env.getContextWrappers().get(0).getData().getAuthentication().getMethod(),
                is(AuthenticationData.METHOD_JSON));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .size(),
                is(3));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_PAGE_URL),
                is("https://www.example.com/login1"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_REQUEST_URL),
                is("https://www.example.com/login1"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getParameters()
                        .get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY),
                is("{\"email\":\"{%username%}\",\"password\":\"{%password%}\"}"));
    }

    @Test
    void shouldLoadVerificationData() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        verification:\n"
                        + "          method: 'poll'\n"
                        + "          loggedInRegex: 'aaa'\n"
                        + "          loggedOutRegex: 'bbb'\n"
                        + "          pollFrequency: 123\n"
                        + "          pollUnits: 'seconds'\n"
                        + "          pollUrl: 'https://www.example.com/poll'\n"
                        + "          pollPostData: 'aaa=bbb&ccc=ddd'\n"
                        + "          pollAdditionalHeaders:\n"
                        + "          - header: 'Content-Type'\n"
                        + "            value: 'application/json'\n"
                        + "          - header: 'X-Requested-With'\n"
                        + "            value: 'XMLHttpRequest'"
                        + "";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertNotNull(env.getContextWrappers().get(0).getData().getAuthentication());
        assertNotNull(
                env.getContextWrappers().get(0).getData().getAuthentication().getVerification());
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getMethod(),
                is(VerificationData.METHOD_POLL));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getLoggedInRegex(),
                is("aaa"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getLoggedOutRegex(),
                is("bbb"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollFrequency(),
                is(123));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollUnits(),
                is(VerificationData.POLL_UNIT_SECONDS));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollUrl(),
                is("https://www.example.com/poll"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollPostData(),
                is("aaa=bbb&ccc=ddd"));
        assertNotNull(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollAdditionalHeaders());
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollAdditionalHeaders()
                        .size(),
                is(2));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollAdditionalHeaders()
                        .get(0)
                        .getHeader(),
                is("Content-Type"));
        assertThat(
                env.getContextWrappers()
                        .get(0)
                        .getData()
                        .getAuthentication()
                        .getVerification()
                        .getPollAdditionalHeaders()
                        .get(0)
                        .getValue(),
                is("application/json"));
    }

    @Test
    void shouldErrorOnBadVerification() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        verification: bad";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!automation.error.env.badverification!")));
    }

    @Test
    void shouldErrorOnBadVerificationElements() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      authentication:\n"
                        + "        verification:\n"
                        + "          method: 'Bad'\n"
                        + "          loggedInRegex: '*'\n"
                        + "          loggedOutRegex: '*'\n"
                        + "          pollFrequency: 'aa'\n"
                        + "          pollUnits: 'minutes'\n"
                        + "          pollAdditionalHeaders: 'string'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(5)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
        assertThat(
                progress.getErrors().get(1),
                is(equalTo("!automation.error.env.verification.type.bad!")));
        assertThat(
                progress.getErrors().get(2),
                is(equalTo("!automation.error.env.verification.pollunits.bad!")));
        assertThat(
                progress.getErrors().get(3),
                is(equalTo("!automation.error.env.verification.loginregex.bad!")));
        assertThat(
                progress.getErrors().get(4),
                is(equalTo("!automation.error.env.verification.logoutregex.bad!")));
    }
}
