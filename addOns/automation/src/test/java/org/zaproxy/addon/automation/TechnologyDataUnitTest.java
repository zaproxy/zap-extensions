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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.utils.I18N;

class TechnologyDataUnitTest {

    @Test
    void shouldInitWithNoExcludes() {
        // Given
        TechnologyData td = new TechnologyData();

        // When
        List<String> exclude = td.getExclude();

        // Then
        assertThat(exclude.size(), is(equalTo(0)));
    }

    @Test
    void shouldInitWithTechSet() {
        // Given
        TechSet set = new TechSet(TechnologyUtilsUnitTest.testTech);
        set.exclude(Tech.Db);
        set.exclude(TechnologyUtilsUnitTest.Db_A);
        set.exclude(TechnologyUtilsUnitTest.Db_B);
        set.exclude(TechnologyUtilsUnitTest.Db_C);
        set.exclude(TechnologyUtilsUnitTest.Lang_C_A);
        TechnologyData td = new TechnologyData(set);

        // When
        List<String> exclude = td.getExclude();

        // Then
        assertThat(exclude.size(), is(equalTo(2)));
        assertThat(exclude.contains(Tech.Db.getName()), is(equalTo(true)));
        assertThat(exclude.contains(TechnologyUtilsUnitTest.Lang_C_A.getName()), is(equalTo(true)));
    }

    @Test
    void shouldInitWithContext() {
        // Given
        TechSet set = new TechSet(TechnologyUtilsUnitTest.testTech);
        set.exclude(Tech.Db);
        set.exclude(TechnologyUtilsUnitTest.Db_A);
        set.exclude(TechnologyUtilsUnitTest.Db_B);
        set.exclude(TechnologyUtilsUnitTest.Db_C);
        set.exclude(TechnologyUtilsUnitTest.Lang_C_B);
        Context context = mock(Context.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));

        context.setTechSet(set);
        TechnologyData td = new TechnologyData(context);

        // When
        List<String> exclude = td.getExclude();

        // Then
        assertThat(exclude.size(), is(equalTo(2)));
        assertThat(exclude.contains(Tech.Db.getName()), is(equalTo(true)));
        assertThat(exclude.contains(TechnologyUtilsUnitTest.Lang_C_B.getName()), is(equalTo(true)));
    }

    @Test
    void shouldInitContextTechnology() {
        // Given
        List<String> set =
                new ArrayList<>(
                        Arrays.asList(Tech.Db.getName(), Tech.Lang.getName(), Tech.C.getName()));
        Context context = mock(Context.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        TechnologyData td = new TechnologyData();
        AutomationProgress progress = new AutomationProgress();

        // When
        td.setExclude(set);
        td.initContextTechnology(context, progress);
        TechSet contextTs = context.getTechSet();

        // Then
        assertThat(contextTs.includes(Tech.Db), is(equalTo(false)));
        assertThat(contextTs.includes(Tech.Lang), is(equalTo(false)));
    }

    @Test
    void shouldParseValidTech() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        include:\n"
                        + "        - MySQL\n"
                        + "        exclude:\n"
                        + "        - db\n"
                        + "        - JAVA";
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
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude(), contains("MySQL"));
        assertThat(techData.getExclude(), contains("db", "JAVA"));
    }

    @Test
    void shouldFailBadTech() {
        // Given
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "      - db\n"
                        + "      - JAVA";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.context.badtech!")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getExclude().size(), is(equalTo(0)));
    }

    @Test
    void shouldFailBadTechType() {
        // Given
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        exclude: 'db'\n"
                        + "        include: 'db'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!automation.error.context.badtechtype!",
                        "!automation.error.context.badtechtype!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude().size(), is(equalTo(0)));
        assertThat(techData.getExclude().size(), is(equalTo(0)));
    }

    @Test
    void shouldHandleListVars() {
        // Given
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  vars:\n"
                        + "    INCLUDE:\n"
                        + "     - MySQL\n"
                        + "    EXCLUDE: [ db, JAVA ]\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        exclude: '${[EXCLUDE]}'\n"
                        + "        include: '${[INCLUDE]}'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude(), contains("MySQL"));
        assertThat(techData.getExclude(), contains("db", "JAVA"));
    }

    @Test
    void shouldErrorOnNonListVars() {
        // Given
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  vars:\n"
                        + "    INCLUDE: '{ \"key\": \"value\" }'\n"
                        + "    EXCLUDE: 'db'\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        exclude: '${[EXCLUDE]}'\n"
                        + "        include: '${[INCLUDE]}'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!automation.error.context.badtechtype!",
                        "!automation.error.context.badtechtype!"));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude().size(), is(equalTo(0)));
        assertThat(techData.getExclude().size(), is(equalTo(0)));
    }

    @Test
    void shouldWarnAndErrorOnMissingListVars() {
        // Given
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        Constant.messages = new I18N(Locale.ENGLISH);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        exclude: '${[EXCLUDE]}'\n"
                        + "        include: '${[INCLUDE]}'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(
                progress.getErrors(),
                contains(
                        "!automation.error.context.badtechtype!",
                        "!automation.error.context.badtechtype!"));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings(),
                contains("!automation.error.env.novar!", "!automation.error.env.novar!"));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude().size(), is(equalTo(0)));
        assertThat(techData.getExclude().size(), is(equalTo(0)));
    }

    @Test
    void shouldWarnOnUnknownTech() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        include:\n"
                        + "        - OS\n"
                        + "        - UnknownInclude\n"
                        + "        exclude:\n"
                        + "        - db\n"
                        + "        - JABA";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(
                progress.getWarnings(),
                contains(
                        "!automation.error.context.unknowntech!",
                        "!automation.error.context.unknowntech!"));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude(), contains("OS", "UnknownInclude"));
        assertThat(techData.getExclude(), contains("db", "JABA"));
    }

    @Test
    void shouldWarnOnUnknownElement() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        MockedStatic<CommandLine> mockedCmdLine = Mockito.mockStatic(CommandLine.class);
        String contextStr =
                "env:\n"
                        + "  contexts:\n"
                        + "    - name: name1\n"
                        + "      urls:\n"
                        + "      - http://www.example.com\n"
                        + "      technology:\n"
                        + "        unknown:\n"
                        + "        - C\n"
                        + "        include:\n"
                        + "        - OS\n"
                        + "        exclude:\n"
                        + "        - Windows\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> data = yaml.load(contextStr);
        LinkedHashMap<?, ?> contextData = (LinkedHashMap<?, ?>) data.get("env");
        AutomationProgress progress = new AutomationProgress();

        // When
        AutomationEnvironment env = new AutomationEnvironment(contextData, progress);
        mockedCmdLine.close();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(env.getContextWrappers().size(), is(equalTo(1)));
        TechnologyData techData = env.getContextWrappers().get(0).getData().getTechnology();
        assertThat(techData.getInclude(), contains("OS"));
        assertThat(techData.getExclude(), contains("Windows"));
    }
}
