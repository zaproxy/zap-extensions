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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.sequence.ExtensionSequence;
import org.zaproxy.zap.extension.zest.ExtensionZest;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link SequenceImportJob}. */
class SequenceImportJobUnitTest extends TestUtils {

    private ScriptType scriptType;
    private ExtensionExim exim;
    private ExtensionZest zest;

    private SequenceImportJob job;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionSequence());

        scriptType = mock(ScriptType.class);
        exim = mock(ExtensionExim.class, withSettings().strictness(Strictness.LENIENT));
        zest = mock(ExtensionZest.class, withSettings().strictness(Strictness.LENIENT));

        job = new SequenceImportJob(scriptType, exim, zest);
    }

    @Test
    void shouldReturnDefaultFields() {
        assertThat(job.getType(), is(equalTo("sequence-import")));
        assertThat(job.getName(), is(equalTo("sequence-import")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
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
        assertThat(params.size(), is(equalTo(4)));
        assertThat(params.get("name"), is(equalTo("")));
        assertThat(params.get("path"), is(equalTo("")));
        assertThat(params.get("assertCode"), is(equalTo("")));
        assertThat(params.get("assertLength"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String name = "Sequence Name";
        String path = "/path/to/file.har";
        String yamlStr =
                "parameters:\n"
                        + "  name: "
                        + name
                        + "\n"
                        + "  path: "
                        + path
                        + "\n  assertCode: true\n  assertLength: 5";
        Object data = new Yaml().load(yamlStr);

        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getName(), is(equalTo(name)));
        assertThat(job.getParameters().getPath(), is(equalTo(path)));
        assertThat(job.getParameters().getAssertCode(), is(equalTo(true)));
        assertThat(job.getParameters().getAssertLength(), is(equalTo(5)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
