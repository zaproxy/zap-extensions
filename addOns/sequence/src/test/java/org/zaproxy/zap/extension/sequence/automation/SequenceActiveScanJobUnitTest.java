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
package org.zaproxy.zap.extension.sequence.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.sequence.ExtensionSequence;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SequenceActiveScanJob}. */
class SequenceActiveScanJobUnitTest extends TestUtils {

    private ExtensionActiveScan ascan;
    private ExtensionSequence seq;

    private SequenceActiveScanJob job;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionSequence());

        ascan = mock(ExtensionActiveScan.class, withSettings().strictness(Strictness.LENIENT));
        seq = mock(ExtensionSequence.class, withSettings().strictness(Strictness.LENIENT));
        job = new SequenceActiveScanJob(seq, ascan);
    }

    @Test
    void shouldReturnDefaultFields() {
        assertThat(job.getType(), is(equalTo("sequence-activeScan")));
        assertThat(job.getName(), is(equalTo("sequence-activeScan")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.ATTACK)));
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given / When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.get("context"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String sequence = "Sequence Name";
        String context = "Context";
        String user = "User";
        String policy = "Policy";
        String yamlStr =
                "parameters:\n"
                        + "  sequence: "
                        + sequence
                        + "\n"
                        + "  context: "
                        + context
                        + "\n"
                        + "  user: "
                        + user
                        + "\n"
                        + "  policy: "
                        + policy
                        + "\n";
        Object data = new Yaml().load(yamlStr);

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.getAllUserNames()).willReturn(List.of(user));

        job.setEnv(env);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getSequence(), is(equalTo(sequence)));
        assertThat(job.getParameters().getContext(), is(equalTo(context)));
        assertThat(job.getParameters().getUser(), is(equalTo(user)));
        assertThat(job.getParameters().getPolicy(), is(equalTo(policy)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
