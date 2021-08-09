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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link JobUtils}. */
class JobUtilsUnitTest {

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

    private static class Data {
        private String valueString;

        Data() {}

        Data(String valueString) {
            this.valueString = valueString;
        }

        public String getValueString() {
            return valueString;
        }

        public void setValueString(String valueString) {
            this.valueString = valueString;
        }
    }
}
