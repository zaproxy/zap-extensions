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
package org.zaproxy.addon.exim.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.utils.I18N;

class ImportJobUnitTest {
    private ExtensionExim extExim;

    @BeforeEach
    void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);

        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        extExim = mock(ExtensionExim.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionExim.class)).willReturn(extExim);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        ImportJob job = new ImportJob();

        // Then
        assertThat(job.getType(), is(equalTo("import")));
        assertThat(job.getName(), is(equalTo("import")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        ImportJob job = new ImportJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(2)));
        assertThat(params.get("type"), is(equalTo("")));
        assertThat(params.get("fileName"), is(equalTo("")));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        String type = "har";
        String fileName = "C:\\Users\\ZAPBot\\Documents\\test file.har";
        String yamlStr = "parameters:\n" + "  type: " + type + "\n" + "  fileName: " + fileName;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        ImportJob job = new ImportJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(job.getParameters().getType(), is(equalTo(type)));
        assertThat(job.getParameters().getFileName(), is(equalTo(fileName)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldFailIfInvalidFile() {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        String yamlStr = "parameters:\n" + "  fileName: 'Invalid file path'";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);

        ImportJob job = new ImportJob();
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().get(0), is(equalTo("!exim.automation.import.error.file!")));
    }
}
