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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.I18N;

public class AutomationJobUnitTest {

    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    public static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    public static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    public void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    public void shouldChangeName() {
        // Given
        AutomationJob job = new AutomationJobImpl();
        String newName = "new-name";

        // When
        String type = job.getType();
        String initialName = job.getName();
        job.setName(newName);
        String afterSetName = job.getName();
        job.setName(null);
        String afterNullName = job.getName();

        // Then
        assertThat(initialName, is(equalTo(type)));
        assertThat(afterSetName, is(equalTo(newName)));
        assertThat(afterNullName, is(equalTo(type)));
    }

    @Test
    public void shouldExtractExpectedParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();

        // When
        Map<String, String> params = job.getConfigParameters(tpc, "getTestParam");

        // Then
        assertThat(params.size(), is(equalTo(5)));
        assertThat(params.containsKey("stringParam"), is(equalTo(true)));
        assertThat(params.containsKey("integerParam"), is(equalTo(true)));
        assertThat(params.containsKey("intParam"), is(equalTo(true)));
        assertThat(params.containsKey("booleanParam"), is(equalTo(true)));
        assertThat(params.containsKey("boolParam"), is(equalTo(true)));
    }

    @Test
    public void shouldExcludeNamedParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job =
                new AutomationJobImpl() {
                    @Override
                    public boolean isExcludeParam(String param) {
                        switch (param) {
                            case "integerParam":
                            case "boolParam":
                                return true;
                            default:
                                return false;
                        }
                    }
                };

        // When
        Map<String, String> params = job.getConfigParameters(tpc, "getTestParam");

        // Then
        assertThat(params.size(), is(equalTo(3)));
        assertThat(params.containsKey("stringParam"), is(equalTo(true)));
        assertThat(params.containsKey("intParam"), is(equalTo(true)));
        assertThat(params.containsKey("booleanParam"), is(equalTo(true)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldSetParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();
        String stringParamValue = "a string";
        int intParamValue = 6;
        Integer integerParamValue = Integer.valueOf(7);
        boolean boolParamValue = true;
        Boolean booleanParamValue = Boolean.FALSE;

        Map map = new HashMap();
        map.put("stringParam", stringParamValue);
        map.put("intParam", Integer.toString(intParamValue));
        map.put("integerParam", integerParamValue.toString());
        map.put("boolParam", Boolean.toString(boolParamValue));
        map.put("booleanParam", booleanParamValue.toString());
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(tpc.getTestParam().getStringParam(), is(equalTo(stringParamValue)));
        assertThat(tpc.getTestParam().getIntParam(), is(equalTo(intParamValue)));
        assertThat(tpc.getTestParam().getIntegerParam(), is(equalTo(integerParamValue)));
        assertThat(tpc.getTestParam().isBoolParam(), is(equalTo(boolParamValue)));
        assertThat(tpc.getTestParam().getBooleanParam(), is(equalTo(booleanParamValue)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldWarnOnUnknownParam() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("unknownParam", "test");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldIgnoreNullParamValue() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("stringParam", null);
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldFailOnBadInt() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("intParam", "Not an int");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldFailOnBadInteger() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        map.put("integerParam", "Not an int");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldFailOnBadBool() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("boolParam", "Not a bool");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);

        // When
        job.applyParameters(tpc, "getTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badbool!")));
    }

    @Test
    public void shouldIgnoreNullParams() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.applyParameters(tpc, "getTestParam", null, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void shouldFailOnBadOptionsGetterName() {
        // Given
        TestParamContainer tpc = new TestParamContainer();
        AutomationJob job = new AutomationJobImpl();
        AutomationProgress progress = new AutomationProgress();

        Map map = new HashMap();
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);
        // When
        job.applyParameters(tpc, "getBadTestParam", params, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.methods!")));
    }

    @Test
    public void shouldReturnDefaultConfigFileData() {
        // Given
        String expectedParams =
                "  - type: type\n"
                        + "    name: type\n"
                        + "    parameters:\n"
                        + "      boolParam: false\n"
                        + "      booleanParam: \n"
                        + "      intParam: 0\n"
                        + "      integerParam: \n"
                        + "      stringParam: \n";

        AutomationJobImpl job = new AutomationJobImpl();
        TestParamContainer tpc = new TestParamContainer();
        job.setParamMethodObject(tpc);

        // When
        String data = job.getConfigFileData();

        // Then
        assertThat(data, is(equalTo(expectedParams)));
    }

    @Test
    public void shouldReturnSetConfigFileData() {
        // Given
        String expectedParams =
                "  - type: type\n"
                        + "    name: type\n"
                        + "    parameters:\n"
                        + "      boolParam: true\n"
                        + "      booleanParam: false\n"
                        + "      intParam: 8\n"
                        + "      integerParam: 9\n"
                        + "      stringParam: testStr\n";

        AutomationJobImpl job = new AutomationJobImpl();
        TestParamContainer tpc = new TestParamContainer();
        job.setParamMethodObject(tpc);
        tpc.getTestParam().setBoolParam(true);
        tpc.getTestParam().setBooleanParam(Boolean.FALSE);
        tpc.getTestParam().setIntParam(8);
        tpc.getTestParam().setIntegerParam(9);
        tpc.getTestParam().setStringParam("testStr");

        // When
        String data = job.getConfigFileData();

        // Then
        assertThat(data, is(equalTo(expectedParams)));
    }

    @Test
    public void shouldCorrectlyOrderJobs() {
        // Given
        AutomationJob lastJob =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Last job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.RUN_LAST;
                    }
                };
        AutomationJob firstJob =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "First job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.RUN_FIRST;
                    }
                };
        AutomationJob explore1Job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Explore 1";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }
                };
        AutomationJob explore2Job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "Explore 2";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }
                };

        ArrayList<AutomationJob> list = new ArrayList<>();
        list.add(explore2Job);
        list.add(lastJob);
        list.add(firstJob);
        list.add(explore1Job);

        // When
        Collections.sort(list);

        // Then
        assertThat(list.size(), is(equalTo(4)));
        assertThat(list.get(0), is(equalTo(firstJob)));
        assertThat(list.get(1), is(equalTo(explore1Job)));
        assertThat(list.get(2), is(equalTo(explore2Job)));
        assertThat(list.get(3), is(equalTo(lastJob)));
    }

    // Methods are accessed via reflection
    private static class TestParamContainer {
        private TestParam testParam = new TestParam();

        public TestParam getTestParam() {
            return testParam;
        }
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParam {

        private String stringParam;
        private Integer integerParam;
        private int intParam;
        private Boolean booleanParam;
        private boolean boolParam;
        private List<String> listStringPram;

        public String getStringParam() {
            return stringParam;
        }

        public void setStringParam(String stringParam) {
            this.stringParam = stringParam;
        }

        public Integer getIntegerParam() {
            return integerParam;
        }

        public void setIntegerParam(Integer integerParam) {
            this.integerParam = integerParam;
        }

        public int getIntParam() {
            return intParam;
        }

        public void setIntParam(int intParam) {
            this.intParam = intParam;
        }

        public Boolean getBooleanParam() {
            return booleanParam;
        }

        public void setBooleanParam(Boolean booleanParam) {
            this.booleanParam = booleanParam;
        }

        public boolean isBoolParam() {
            return boolParam;
        }

        public void setBoolParam(boolean boolParam) {
            this.boolParam = boolParam;
        }

        public List<String> getListStringPram() {
            return listStringPram;
        }

        public void setListStringPram(List<String> listStringPram) {
            this.listStringPram = listStringPram;
        }

        public boolean getWithOneParam(String test) {
            return test.length() > 0;
        }

        public void setWithOneParam(String test) {}

        public boolean getWithNoSetter() {
            return false;
        }
    }

    private static class AutomationJobImpl extends AutomationJob {

        private Object paramMethodObject;

        @Override
        public void runJob(
                AutomationEnvironment env,
                LinkedHashMap<?, ?> jobData,
                AutomationProgress progress) {}

        @Override
        public String getType() {
            return "type";
        }

        @Override
        public Order getOrder() {
            return null;
        }

        @Override
        public Object getParamMethodObject() {
            return paramMethodObject;
        }

        @Override
        public String getParamMethodName() {
            return "getTestParam";
        }

        public void setParamMethodObject(Object o) {
            paramMethodObject = o;
        }
    }
}
