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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link JobUtils}. */
class JobUtilsUnitTest {

    enum enumeration {
        aaa,
        bbb
    };

    @BeforeAll
    static void setUp() {
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldApplyObjectToObject() {
        // Given
        Data source = new Data("A");
        Data dest = new Data();
        AutomationProgress progress = mock(AutomationProgress.class);
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any())).willAnswer(invocation -> invocation.getArgument(0));
        // When
        JobUtils.applyObjectToObject(source, dest, "name", new String[] {}, progress, env);
        // Then
        assertThat(dest.getValueString(), is(equalTo("A")));
    }

    @Test
    void shouldApplyObjectToObjectWhileIgnoringSpecifiedPropertyNames() {
        // Given
        Data source = new Data("A");
        Data dest = new Data();
        AutomationProgress progress = mock(AutomationProgress.class);
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any())).willAnswer(invocation -> invocation.getArgument(0));
        // When
        JobUtils.applyObjectToObject(
                source, dest, "name", new String[] {"valueString"}, progress, env);
        // Then
        assertThat(dest.getValueString(), is(nullValue()));
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
    }

    private static class Data {
        private String valueString;

        Data() {}

        Data(String valueString) {
            this.valueString = valueString;
        }

        public String getValueString() {
            return valueString;
        }

        @SuppressWarnings("unused")
        // Used by reflection
        public void setValueString(String valueString) {
            this.valueString = valueString;
        }
    }
}
