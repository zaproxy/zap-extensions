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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
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
import org.zaproxy.zap.utils.I18N;

class AutomationEnvironmentUnitTest {

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
    void shouldFailIfNoData() {
        // Given
        String contextStr = "env:";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.env.missing!")));
    }

    @Test
    void shouldFailIfNoContexts() {
        // Given
        String contextStr = "env:\n" + "  contexts:\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.env.nocontexts!")));
    }

    @Test
    void shouldFailIfBadContexts() {
        // Given
        String contextStr = "env:\n" + "  contexts:\n" + "    param1: value 1\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.env.badcontexts!")));
    }

    @Test
    void shouldFailIfNoContextUrl() {
        // Given
        String contextStr = "env:\n" + "  contexts:\n" + "    - name: test\n" + "      urls: \n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.nourl!")));
    }

    @Test
    void shouldFailIfNoContextName() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: \n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.noname!")));
    }

    @Test
    void shouldFailIfBadContextUrl() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: test\n"
                        + "      urls:\n"
                        + "      - Not a url\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badurl!")));
    }

    @Test
    void shouldFailAtRunTimeIfBadContextUrl() {
        // Given
        // Note that URLs containing env vrs are not checked on load
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: test\n"
                        + "      urls:\n"
                        + "      - Not a url with ${envvar}\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badurl!")));
    }

    @Test
    void shouldSucceedWithValidContext() {
        // Given
        String contextName = "context 1";
        String exampleUrl = "https://www.example.com/";
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: "
                        + contextName
                        + "\n"
                        + "      urls:\n"
                        + "      - "
                        + exampleUrl
                        + "\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(0)));
        assertThat(contexts.size(), is(equalTo(1)));
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example.com/.*");
        assertThat(env.isFailOnError(), is(equalTo(true)));
        assertThat(env.isFailOnWarning(), is(equalTo(false)));
        assertThat(env.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldSucceedWithValidContextWithMultipleUrls() {
        // Given
        String contextName = "context 1";
        String exampleUrl1 = "https://www.example.com/";
        String exampleUrl2 = "http://www.example.com/";
        String exampleUrl3 = "https://www.example.org/";
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: "
                        + contextName
                        + "\n"
                        + "      urls: \n"
                        + "      - "
                        + exampleUrl1
                        + "\n"
                        + "      - "
                        + exampleUrl2
                        + "\n"
                        + "      - "
                        + exampleUrl3
                        + "\n"
                        + "\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<ContextWrapper> contextWrappers = env.getContextWrappers();
        List<Context> contexts = env.getContexts();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(0)));
        assertThat(contextWrappers.size(), is(equalTo(1)));
        assertThat(contextWrappers.get(0).getUrls().size(), is(equalTo(3)));
        assertThat(
                contextWrappers.get(0).getUrls(), contains(exampleUrl1, exampleUrl2, exampleUrl3));
        assertThat(contexts.size(), is(equalTo(1)));
        verify(contexts.get(0)).addIncludeInContextRegex(exampleUrl1 + ".*");
        verify(contexts.get(0)).addIncludeInContextRegex(exampleUrl2 + ".*");
        verify(contexts.get(0)).addIncludeInContextRegex(exampleUrl3 + ".*");
        assertThat(env.isFailOnError(), is(equalTo(true)));
        assertThat(env.isFailOnWarning(), is(equalTo(false)));
        assertThat(env.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldSucceedWith2ValidContexts() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example1.com/\n"
                        + "    - name: context 2\n"
                        + "      urls:\n"
                        + "      - https://www.example2.com/\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(0)));
        assertThat(contexts.size(), is(equalTo(2)));
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example1.com/.*");
        verify(contexts.get(1)).addIncludeInContextRegex("https://www.example2.com/.*");
        assertThat(env.isFailOnError(), is(equalTo(true)));
        assertThat(env.isFailOnWarning(), is(equalTo(false)));
        assertThat(env.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfBadIncludeRegexList() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      includePaths: https://www.testregex.example.com.*";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.context.badincludelist!")));
    }

    @Test
    void shouldFailIfBadExcludeRegexList() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      excludePaths: https://www.testregex.example.com.*";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.context.badexcludelist!")));
    }

    @Test
    void shouldFailIfBadIncludeRegexValue() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      includePaths:\n"
                        + "      - Test\\";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badregex!")));
    }

    @Test
    void shouldFailIfBadExcludeRegexValue() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      excludePaths:\n"
                        + "      - Test\\";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badregex!")));
    }

    @Test
    void shouldAddIncludeInContextRegexes() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      includePaths:\n"
                        + "        - https://www.firstregex.example.com.*\n"
                        + "        - https://www.secondregex.example.com.*\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example.com.*");
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.firstregex.example.com.*");
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.secondregex.example.com.*");
    }

    @Test
    void shouldAddExcludeFromContextRegexes() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      excludePaths:\n"
                        + "        - https://www.firstregex.example.com.*\n"
                        + "        - https://www.secondregex.example.com.*\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example.com.*");
        verify(contexts.get(0)).addExcludeFromContextRegex("https://www.firstregex.example.com.*");
        verify(contexts.get(0)).addExcludeFromContextRegex("https://www.secondregex.example.com.*");
    }

    @Test
    void shouldSetResolvedIncludeRegexes() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      includePaths:\n"
                        + "        - https://www.${myPrefix}.${myEnvVar}.example.com.*\n"
                        + "  vars:\n"
                        + "    myPrefix: prefix\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example.com.*");
        verify(contexts.get(0))
                .addIncludeInContextRegex("https://www.prefix.envVarValue.example.com.*");
    }

    @Test
    void shouldSetResolvedExcludeRegexes() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "      excludePaths:\n"
                        + "        - https://www.${myPrefix}.${myEnvVar}.example.com.*\n"
                        + "  vars:\n"
                        + "    myPrefix: prefix\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.example.com.*");
        verify(contexts.get(0))
                .addExcludeFromContextRegex("https://www.prefix.envVarValue.example.com.*");
    }

    @Test
    void shouldSetValidParams() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnError: false\n"
                        + "    failOnWarning: true\n"
                        + "    progressToStdout: true\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment ae = new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getWarnings().size(), is(equalTo(0)));
        assertThat(ae.isFailOnError(), is(equalTo(false)));
        assertThat(ae.isFailOnWarning(), is(equalTo(true)));
        assertThat(ae.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldWarnOnUnrecognisedEnvParams() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnError: false\n"
                        + "    failOnWarning: true\n"
                        + "    progressToStdout: true\n"
                        + "    unknown2: test\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
    }

    @Test
    void shouldWarnOnUnrecognisedContextParams() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      unknown2: test\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnError: false\n"
                        + "    failOnWarning: true\n"
                        + "    progressToStdout: true\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(0)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
    }

    @Test
    void shouldBeTimeToQuitOnErrorIfOptionSet() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnError: true\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        progress.error("Test");

        // Then
        assertThat(env.isTimeToQuit(), is(equalTo(true)));
    }

    @Test
    void shouldNotBeTimeToQuitOnErrorIfOptionNotSet() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnError: false\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        progress.error("Test");

        // Then
        assertThat(env.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldBeTimeToQuitOnWarningIfOptionSet() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnWarning: true\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        progress.warn("Test");

        // Then
        assertThat(env.isTimeToQuit(), is(equalTo(true)));
    }

    @Test
    void shouldNotBeTimeToQuitOnWarningIfOptionNotSet() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.example.com\n"
                        + "  parameters:\n"
                        + "    failOnWarning: false\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        progress.warn("Test");

        // Then
        assertThat(env.isTimeToQuit(), is(equalTo(false)));
    }

    @Test
    void shouldReplaceConfigVarsInEnv() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.${myPrefix}.example.com\n"
                        + "  vars:\n"
                        + "    myPrefix: prefix\n"
                        + "    myVar: ${myPrefix}.suffix\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        assertThat(env.getData().getVars().get("myPrefix"), is(equalTo("prefix")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertThat(contexts.size(), is(equalTo(1)));
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.prefix.example.com.*");
    }

    @Test
    void shouldUseSystemEnvVarsOverConfigVars() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      urls:\n"
                        + "      - https://www.${myEnvVar}.example.com\n"
                        + "  vars:\n"
                        + "    myEnvVar: configVar\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        assertThat(env.getData().getVars().get("myEnvVar"), is(equalTo("configVar")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        assertThat(contexts.size(), is(equalTo(1)));
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.envVarValue.example.com.*");
    }

    @Test
    void shouldReplaceEnvVarsInJobs() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context ${myVar2}\n"
                        + "      urls:\n"
                        + "      - https://www.${myEnvVar}.example.com\n"
                        + "  vars:\n"
                        + "    myVar: ${myEnvVar}.suffix\n"
                        + "    myVar2: blah\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        env.create(session, progress);
        List<Context> contexts = env.getContexts();

        // Then
        verify(contexts.get(0)).addIncludeInContextRegex("https://www.envVarValue.example.com.*");
        assertThat(env.getData().getVars().get("myVar"), is(equalTo("${myEnvVar}.suffix")));
        assertThat(
                env.getContextWrappers().get(0).getData().getName(),
                is(equalTo("context ${myVar2}")));
        verify(session).getNewContext("context blah");
    }

    @Test
    void shouldWarnOnSingleUrl() {
        // Given
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: context 1\n"
                        + "      url: https://www.example.com\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        new AutomationEnvironment(contextData, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!automation.error.context.url.deprecated!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }
}
