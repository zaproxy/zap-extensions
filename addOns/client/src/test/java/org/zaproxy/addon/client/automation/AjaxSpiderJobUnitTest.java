/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.testutils.TestUtils;

class AjaxSpiderJobUnitTest extends TestUtils {

    private static final String CLIENT_SPIDER_WARN =
            "The AJAX Spider has been superseded by the Client Spider, so using that instead.";

    @BeforeEach
    void setUp() {
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionClientIntegration extClient = mock(ExtensionClientIntegration.class);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class)).willReturn(extClient);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        mockMessages(new ExtensionClientIntegration());
    }

    @Test
    void shouldHaveAjaxSpiderType() {
        // Given / When
        AjaxSpiderJob job = new AjaxSpiderJob();

        // Then
        assertThat(job.getType(), is(equalTo("spiderAjax")));
    }

    @Test
    void shouldWarnClientSpiderIsUsedEvenWithoutParameters() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        job.setJobData(null);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(
                progress.getWarnings(),
                contains(Constant.messages.getString("client.automation.ajaxSpiderJob.warn")));
        assertThat(progress.getWarnings(), contains(CLIENT_SPIDER_WARN));
    }

    @Test
    void shouldIgnoreUnsupportedAjaxSpiderOnlyParametersWithoutError() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
                parameters:
                  url:                     https://www.example.com/test/
                  clickDefaultElems:       true
                  clickElemsOnce:          true
                  elements:                [a, button]
                  enableExtensions:        true
                  eventWait:               1000
                  excludedElements:        []
                  failIfFoundUrlsLessThan: 10
                  inScopeOnly:             true
                  maxCrawlStates:          10
                  randomInputs:            true
                  reloadWait:              1000
                  warnIfFoundUrlsLessThan: 20
                """;
        Yaml yaml = new Yaml();
        job.setJobData((LinkedHashMap<?, ?>) yaml.load(yamlStr));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings(), hasSize(1));
        assertThat(progress.getWarnings(), contains(CLIENT_SPIDER_WARN));
        assertThat(job.getParameters().getUrl(), is(equalTo("https://www.example.com/test/")));
    }

    @Test
    void shouldApplySupportedParametersInCommonWithClientSpider() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
                parameters:
                  context:         testContext
                  url:             https://www.example.com/test/
                  logoutAvoidance: false
                  runOnlyIfModern: true
                """;
        Yaml yaml = new Yaml();
        job.setJobData((LinkedHashMap<?, ?>) yaml.load(yamlStr));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings(), hasSize(1));
        assertThat(job.getParameters().getContext(), is(equalTo("testContext")));
        assertThat(job.getParameters().getUrl(), is(equalTo("https://www.example.com/test/")));
        assertThat(job.getParameters().getLogoutAvoidance(), is(equalTo(false)));
        assertThat(job.getParameters().getRunOnlyIfModern(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadTemplate(boolean minTemplate) {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        Yaml yaml = new Yaml();
        Object data;
        if (minTemplate) {
            data = yaml.load(job.getTemplateDataMin());
        } else {
            data = yaml.load(job.getTemplateDataMax());
        }
        job.setJobData(((LinkedHashMap<?, ?>) ((ArrayList<?>) data).get(0)));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings(), contains(CLIENT_SPIDER_WARN));
        assertThat(job.getType(), is(equalTo("spiderAjax")));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldHaveValidTemplates(boolean minTemplate) {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();

        // When
        String template = minTemplate ? job.getTemplateDataMin() : job.getTemplateDataMax();

        // Then
        assertThat(template, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(template));
    }

    @Test
    void shouldStillWarnOfGenuinelyUnrecognisedParameters() {
        // Given
        AjaxSpiderJob job = new AjaxSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
                parameters:
                  notARealParam: true
                """;
        Yaml yaml = new Yaml();
        job.setJobData((LinkedHashMap<?, ?>) yaml.load(yamlStr));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.getWarnings(), hasSize(2));
        assertThat(progress.getWarnings().get(0), is(equalTo(CLIENT_SPIDER_WARN)));
    }
}
