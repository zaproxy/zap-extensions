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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link JobUtils}. */
class JobUtilsUnitTest extends TestUtils {

    enum enumeration {
        aaa,
        bbb
    };

    @BeforeAll
    static void setUp() {
        Constant.messages = new I18N(Locale.getDefault());
    }

    @Test
    void shouldApplyParamsToObject() {
        // Given
        mockMessages(new ExtensionAutomation());
        AutomationProgress progress = mock(AutomationProgress.class);
        HashMap<String, Object> src = new HashMap<>();
        src.put("bool", "true");
        src.put("valueString", "String");
        src.put("array", List.of(1, "A"));
        src.put("list", List.of(2, "B"));
        Data dest = new Data();
        // When
        JobUtils.applyParamsToObject(src, dest, "name", null, progress);
        // Then
        verify(progress).info("Job name set bool = true");
        assertThat(dest.isBool(), is(equalTo(Boolean.TRUE)));
        verify(progress).info("Job name set valueString = String");
        assertThat(dest.getValueString(), is(equalTo("String")));
        verify(progress).info("Job name set array = [1, A]");
        assertThat(dest.getArray(), is(equalTo(new Object[] {1, "A"})));
        verify(progress).info("Job name set list = [2, B]");
        assertThat(dest.getList(), is(equalTo(List.of(2, "B"))));
    }

    @Test
    void shouldApplyObjectToObject() {
        // Given
        Data source = new Data("A", Boolean.TRUE);
        Data dest = new Data();
        AutomationProgress progress = mock(AutomationProgress.class);
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any())).willAnswer(invocation -> invocation.getArgument(0));
        // When
        JobUtils.applyObjectToObject(source, dest, "name", new String[] {}, progress, env);
        // Then
        assertThat(dest.getValueString(), is(equalTo("A")));
        assertThat(dest.isBool(), is(equalTo(Boolean.TRUE)));
    }

    @Test
    void shouldApplyObjectToObjectWhileIgnoringSpecifiedPropertyNames() {
        // Given
        Data source = new Data("A", Boolean.TRUE);
        Data dest = new Data();
        AutomationProgress progress = mock(AutomationProgress.class);
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        // When
        JobUtils.applyObjectToObject(
                source, dest, "name", new String[] {"valueString", "bool"}, progress, env);
        // Then
        assertThat(dest.getValueString(), is(nullValue()));
        assertThat(dest.isBool(), is(nullValue()));
    }

    @Test
    void shouldGetJobPrivateOptions() {
        // Given
        AutomationJob job =
                new AutomationJob() {

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {}

                    @Override
                    public String getType() {
                        return null;
                    }

                    @Override
                    public Order getOrder() {
                        return null;
                    }

                    @Override
                    public Object getParamMethodObject() {
                        return this;
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getParams";
                    }

                    @SuppressWarnings("unused")
                    private String getParams() {
                        return "params";
                    }
                };
        AutomationProgress progress = mock(AutomationProgress.class);
        // When
        Object options = JobUtils.getJobOptions(job, progress);
        // Then
        assertThat(options, is("params"));
    }

    @Test
    void shouldErrorIfCannotAccessJobPrivateOptions() {
        // Given
        AutomationJob job =
                new AutomationJob() {

                    @Override
                    public void runJob(AutomationEnvironment env, AutomationProgress progress) {}

                    @Override
                    public String getType() {
                        return null;
                    }

                    @Override
                    public Order getOrder() {
                        return null;
                    }

                    @Override
                    public Object getParamMethodObject() {
                        return this;
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getParams";
                    }
                };
        AutomationProgress progress = new AutomationProgress();
        // When
        Object options = JobUtils.getJobOptions(job, progress);
        // Then
        assertThat(options, is(nullValue()));
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.getErrors().size(), is(1));
    }

    @Test
    void shouldApplyObjectToType() {
        // Given
        HashMap<String, String> hmap = new HashMap<>();
        hmap.put("aaa", "bbb");
        hmap.put("ccc", "ddd");

        // When
        Object string = JobUtils.objectToType("string", String.class);
        Object integer5 = JobUtils.objectToType("5", Integer.class);
        Object integer6 = JobUtils.objectToType("6", int.class);
        Object long7 = JobUtils.objectToType("7", Long.class);
        Object long8 = JobUtils.objectToType("8", long.class);
        Object boolTrue = JobUtils.objectToType("TRUe", boolean.class);
        Object booleanTrue = JobUtils.objectToType("trUe", boolean.class);
        Object boolFalse = JobUtils.objectToType("falSE", boolean.class);
        Object booleanFalse = JobUtils.objectToType("FALSe", boolean.class);
        Object enumAAA = JobUtils.objectToType("aAa", enumeration.class);
        Object enumBBB = JobUtils.objectToType("bbB", enumeration.class);
        Object map = JobUtils.objectToType(hmap, Map.class);

        Class<String[]> stringArrayClass = String[].class;
        List<String> strList = new ArrayList<>();
        strList.add("str");
        Object strArray = JobUtils.objectToType(strList, stringArrayClass);

        Class<Integer[]> intArrayClass = Integer[].class;
        List<Integer> intList = new ArrayList<>();
        intList.add(3);
        intList.add(9);
        Object intArray = JobUtils.objectToType(intList, intArrayClass);

        // Then
        assertThat(string, is(equalTo("string")));
        assertThat(integer5, is(equalTo(5)));
        assertThat(integer6, is(equalTo(6)));
        assertThat(long7, is(equalTo(7L)));
        assertThat(long8, is(equalTo(8L)));
        assertThat(boolTrue, is(equalTo(true)));
        assertThat(booleanTrue, is(equalTo(true)));
        assertThat(boolFalse, is(equalTo(false)));
        assertThat(booleanFalse, is(equalTo(false)));
        assertThat(enumAAA, is(equalTo(enumeration.aaa)));
        assertThat(enumBBB, is(equalTo(enumeration.bbb)));
        assertThat(map.getClass(), is(equalTo(HashMap.class)));
        assertThat(((Map<?, ?>) map).size(), is(equalTo(2)));
        assertThat(strArray.getClass(), is(equalTo(stringArrayClass)));
        assertThat(((String[]) strArray).length, is(equalTo(1)));
        assertThat(((String[]) strArray)[0], is(equalTo("str")));
        assertThat(intArray.getClass(), is(equalTo(intArrayClass)));
        assertThat(((Integer[]) intArray).length, is(equalTo(2)));
        assertThat(((Integer[]) intArray)[0], is(equalTo(3)));
        assertThat(((Integer[]) intArray)[1], is(equalTo(9)));
    }

    @Test
    void shouldNotGetScriptWrapperIfExtensionScriptDisabled() {
        // Given
        mockExtensionLoader(null);
        File file = new File("/script.ext");
        String type = "type";
        String engineName = "engine";
        AutomationProgress progress = mock(AutomationProgress.class);
        // When
        ScriptWrapper obtainedScriptWrapper =
                JobUtils.getScriptWrapper(file, type, engineName, progress);
        // Then
        assertThat(obtainedScriptWrapper, is(nullValue()));
        verifyNoInteractions(progress);
    }

    @Test
    void shouldGetExistingScriptWrapper() {
        // Given
        ExtensionScript extensionScript = mockExtensionLoader(mock(ExtensionScript.class));
        File file = new File("/script.ext");
        String type = "type";
        String engineName = "engine";
        AutomationProgress progress = mock(AutomationProgress.class);
        ScriptWrapper otherScriptWrapper = mock(ScriptWrapper.class);
        given(otherScriptWrapper.getFile()).willReturn(new File("/other-script.ext"));
        ScriptWrapper otherScriptWrapper2 = mock(ScriptWrapper.class);
        given(otherScriptWrapper2.getFile()).willReturn(file);
        given(otherScriptWrapper2.getEngineName()).willReturn("other engine");
        ScriptWrapper scriptWrapper = mock(ScriptWrapper.class);
        given(scriptWrapper.getFile()).willReturn(file);
        given(scriptWrapper.getEngineName()).willReturn(engineName);
        given(extensionScript.getScripts(type))
                .willReturn(Arrays.asList(otherScriptWrapper, otherScriptWrapper2, scriptWrapper));
        // When
        ScriptWrapper obtainedScriptWrapper =
                JobUtils.getScriptWrapper(file, type, engineName, progress);
        // Then
        assertThat(obtainedScriptWrapper, is(sameInstance(scriptWrapper)));
        verifyNoInteractions(progress);
    }

    @Test
    void shouldAddScriptWrapperIfNotPresent() throws Exception {
        // Given
        ExtensionScript extensionScript = mockExtensionLoader(mock(ExtensionScript.class));
        File file = new File("/script.ext");
        String type = "type";
        String engineName = "engine";
        AutomationProgress progress = mock(AutomationProgress.class);
        ScriptEngineWrapper scriptEngineWrapper = mock(ScriptEngineWrapper.class);
        given(extensionScript.getEngineWrapper(engineName)).willReturn(scriptEngineWrapper);
        ScriptWrapper scriptWrapperLoaded = mock(ScriptWrapper.class);
        given(extensionScript.loadScript(any())).willReturn(scriptWrapperLoaded);
        ScriptWrapper scriptWrapperAdded = mock(ScriptWrapper.class);
        ScriptNode node = mock(ScriptNode.class);
        given(node.getUserObject()).willReturn(scriptWrapperAdded);
        given(extensionScript.addScript(scriptWrapperLoaded, false)).willReturn(node);
        // When
        ScriptWrapper obtainedScriptWrapper =
                JobUtils.getScriptWrapper(file, type, engineName, progress);
        // Then
        assertThat(obtainedScriptWrapper, is(sameInstance(scriptWrapperAdded)));
        verifyNoInteractions(progress);
    }

    @Test
    void shouldNotAddScriptWrapperIfEngineNotPresent() {
        // Given
        ExtensionScript extensionScript = mockExtensionLoader(mock(ExtensionScript.class));
        File file = new File("/script.ext");
        String type = "type";
        String engineName = "engine";
        given(extensionScript.getEngineWrapper(engineName)).willReturn(null);
        AutomationProgress progress = mock(AutomationProgress.class);
        // When
        ScriptWrapper obtainedScriptWrapper =
                JobUtils.getScriptWrapper(file, type, engineName, progress);
        // Then
        verify(progress).error("!automation.error.env.sessionmgmt.engine.bad!");
        assertThat(obtainedScriptWrapper, is(nullValue()));
    }

    @Test
    void shouldReturnFileFromFullPath() {
        // Given
        String path = "/full/path/to/file";
        AutomationPlan plan = new AutomationPlan();
        // When
        File f = JobUtils.getFile(path, plan);
        // Then
        assertFilePath(f, path);
    }

    @Test
    void shouldReturnFileFromFullPathWithVars() {
        // Given
        String path = "/full/${var1}/to/${var2}";
        AutomationPlan plan = new AutomationPlan();
        plan.getEnv().getData().getVars().put("var1", "path");
        plan.getEnv().getData().getVars().put("var2", "file");
        // When
        File f = JobUtils.getFile(path, plan);
        // Then
        assertFilePath(f, "/full/path/to/file");
    }

    @Test
    void shouldReturnFileFromFullPathWithVarsAndFilePlan() {
        // Given
        String path = "${var1}/to/${var2}";
        AutomationPlan plan = new AutomationPlan();
        plan.setFile(new File("/full/path/dir/plan"));
        plan.getEnv()
                .getData()
                .getVars()
                .put("var1", Paths.get("/full/path").toAbsolutePath().toString());
        plan.getEnv().getData().getVars().put("var2", "file");
        // When
        File f = JobUtils.getFile(path, plan);
        // Then
        assertFilePath(f, "/full/path/to/file");
    }

    @Test
    void shouldReturnFileFromRelativePath() {
        // Given
        String path = "../relative/path/to/file";
        AutomationPlan plan = new AutomationPlan();
        plan.setFile(new File("/full/path/dir/plan"));
        // When
        File f = JobUtils.getFile(path, plan);
        // Then
        assertFilePath(f, "/full/path/relative/path/to/file");
    }

    @Test
    void shouldReturnFileFromRelativePathWithVars() {
        // Given
        String path = "${var2}/path/${var1}/file";
        AutomationPlan plan = new AutomationPlan();
        plan.setFile(new File("/full/path/dir/plan"));
        plan.getEnv().getData().getVars().put("var1", "to");
        plan.getEnv().getData().getVars().put("var2", "relative");
        // When
        File f = JobUtils.getFile(path, plan);
        // Then
        assertFilePath(f, "/full/path/dir/relative/path/to/file");
    }

    static Stream<Locale> locales() {
        return Stream.of(
                Locale.ROOT, Locale.ENGLISH, new Locale.Builder().setLanguage("TR").build());
    }

    @ParameterizedTest
    @MethodSource("locales")
    void shouldParseAttackStrengthInDifferentLocales(Locale locale) {
        Locale defaultLocale = Locale.getDefault();
        try {
            // Given
            Locale.setDefault(locale);
            AutomationProgress progress = mock(AutomationProgress.class);
            // When
            AttackStrength attackStrength = JobUtils.parseAttackStrength("medium", "job", progress);
            // Then
            assertThat(attackStrength, is(equalTo(AttackStrength.MEDIUM)));
            verifyNoInteractions(progress);
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    @ParameterizedTest
    @MethodSource("locales")
    void shouldParseAlertThresholdInDifferentLocales(Locale locale) {
        Locale defaultLocale = Locale.getDefault();
        try {
            // Given
            Locale.setDefault(locale);
            AutomationProgress progress = mock(AutomationProgress.class);
            // When
            AlertThreshold alertThreshold = JobUtils.parseAlertThreshold("medium", "job", progress);
            // Then
            assertThat(alertThreshold, is(equalTo(AlertThreshold.MEDIUM)));
            verifyNoInteractions(progress);
        } finally {
            Locale.setDefault(defaultLocale);
        }
    }

    private static void assertFilePath(File file, String path) {
        assertThat(
                file.toPath().normalize().toAbsolutePath(), is(Paths.get(path).toAbsolutePath()));
    }

    private static ExtensionScript mockExtensionLoader(ExtensionScript extensionScript) {
        Model model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        Control.initSingletonForTesting(model, extensionLoader);
        given(extensionLoader.getExtension(ExtensionScript.class)).willReturn(extensionScript);
        return extensionScript;
    }

    static class Data {
        private String valueString;
        private Boolean bool;
        private Object[] array;
        private List<Object> list;

        Data() {}

        Data(String valueString, Boolean bool) {
            this.valueString = valueString;
            this.bool = bool;
        }

        public String getValueString() {
            return valueString;
        }

        public void setValueString(String valueString) {
            this.valueString = valueString;
        }

        public Boolean isBool() {
            return bool;
        }

        public void setBool(Boolean bool) {
            this.bool = bool;
        }

        public Object[] getArray() {
            return array;
        }

        public void setArray(Object[] array) {
            this.array = array;
        }

        public List<Object> getList() {
            return list;
        }

        public void setList(List<Object> list) {
            this.list = list;
        }
    }
}
