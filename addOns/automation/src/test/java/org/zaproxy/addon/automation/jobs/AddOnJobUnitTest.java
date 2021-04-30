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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
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
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.autoupdate.ExtensionAutoUpdate;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class AddOnJobUnitTest {

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        AddOnJob job = new AddOnJob();

        // Then
        assertThat(job.getType(), is(equalTo("addOns")));
        assertThat(job.getName(), is(equalTo("addOns")));
        assertThat(job.getOrder(), is(equalTo(Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldReturnCustomConfigParams() {
        // Given
        AddOnJob job = new AddOnJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(1)));
        assertThat(params.containsKey("updateAddOns"), is(equalTo(true)));
        assertThat(params.containsValue("true"), is(equalTo(true)));
    }

    @Test
    void shouldApplyCustomConfigParams() {
        // Given
        AddOnJob job = new AddOnJob();

        // When
        job.applyCustomParameter("updateAddOns", "false");

        // Then
        assertThat(job.isUpdateAddOns(), is(equalTo(false)));
    }

    @Test
    void shouldIgnoreUnknownCustomConfigParams() {
        // Given
        AddOnJob job = new AddOnJob();

        // When / Than
        assertFalse(job.applyCustomParameter("test", "test"));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldApplyParams() {
        // Given
        AddOnJob job = new AddOnJob();
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("updateAddOns", "false");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);

        // When
        job.applyParameters(params, progress);

        // Then
        assertThat(job.isUpdateAddOns(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void shouldWarnOnUnknownParams() {
        // Given
        AddOnJob job = new AddOnJob();
        AutomationProgress progress = new AutomationProgress();
        Map map = new HashMap();
        map.put("updateAddOns", "true");
        map.put("test", "test");
        LinkedHashMap<?, ?> params = new LinkedHashMap(map);

        // When
        job.applyParameters(params, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReturnFileConfigData() {
        // Given
        AddOnJob job = new AddOnJob();

        // When
        String data = job.getConfigFileData();

        // Then
        assertThat(data.length(), is(equalTo(264)));
    }

    @Test
    void shouldCheckForUpdatesByDefault() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        // It won't work with the mocked classes, but this is an indication is went down the right
        // path
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.addons.update!")));
    }

    @Test
    void shouldPassIfNothingToDo() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n  updateAddOns: false\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldTryToInstallAddOns() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);
        given(extAuto.installAddOns(any())).willReturn("");

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n  updateAddOns: false\n" + "install: \n  - addon";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReportInstallAddOnsFailure() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        String failureMessage = "Failed";
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);
        given(extAuto.installAddOns(any())).willReturn(failureMessage);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n  updateAddOns: false\n" + "install: \n  - addon";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo(failureMessage)));
    }

    @Test
    void shouldTryToUninstallAddOns() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);
        given(extAuto.uninstallAddOns(any())).willReturn("");

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n  updateAddOns: false\n" + "uninstall: \n  - addon";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @Test
    void shouldReportUninstallAddOnsFailure() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        String failureMessage = "Failed";
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());
        ExtensionAutoUpdate extAuto = mock(ExtensionAutoUpdate.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionAutoUpdate.class)).willReturn(extAuto);
        given(extAuto.uninstallAddOns(any())).willReturn(failureMessage);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);

        AddOnJob job = new AddOnJob();
        String contextStr = "parameters: \n  updateAddOns: false\n" + "uninstall: \n  - addon";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData =
                yaml.load(new ByteArrayInputStream(contextStr.getBytes(StandardCharsets.UTF_8)));

        // When
        job.applyParameters((LinkedHashMap<?, ?>) jobData.get("parameters"), progress);
        job.runJob(env, jobData, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo(failureMessage)));
    }
}
