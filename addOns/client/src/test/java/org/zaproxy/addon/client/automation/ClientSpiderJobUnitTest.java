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
package org.zaproxy.addon.client.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import org.apache.commons.httpclient.URIException;
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
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob.Order;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ContextWrapper;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.spider.ClientSpider;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

public class ClientSpiderJobUnitTest extends TestUtils {

    private ExtensionLoader extensionLoader;
    private ExtensionClientIntegration extClient;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionClientIntegration());

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extClient = mock(ExtensionClientIntegration.class);
        given(extensionLoader.getExtension(ExtensionClientIntegration.class)).willReturn(extClient);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
    }

    @Test
    void shouldReturnDefaultFieldsAndValues() {
        // Given / When
        ClientSpiderJob job = new ClientSpiderJob();

        // Then
        assertDefaultJob(job);
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
    }

    @Test
    void shouldVerifyWithoutParameters() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        ClientSpiderJob job = new ClientSpiderJob();
        job.setJobData(null);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldLoadTemplate(boolean minTemplate) {
        // Given
        ClientSpiderJob job = new ClientSpiderJob();
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
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertDefaultJob(job);
    }

    @Test
    void shouldSetDefaultParameters() {
        // Given
        ClientSpiderJob job = new ClientSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr = "parameters:";
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getParameters().getContext(), is(equalTo("")));
        assertThat(job.getParameters().getUser(), is(equalTo("")));
        assertThat(job.getParameters().getUrl(), is(equalTo("")));
        assertThat(job.getParameters().getMaxDuration(), is(nullValue()));
        assertThat(job.getParameters().getMaxCrawlDepth(), is(ClientOptions.DEFAULT_MAX_DEPTH));
        assertThat(job.getParameters().getMaxChildren(), is(nullValue()));
        assertThat(
                job.getParameters().getNumberOfBrowsers(),
                is(Constants.getDefaultThreadCount() / 2));
        assertThat(job.getParameters().getBrowserId(), is(nullValue()));
        assertThat(
                job.getParameters().getInitialLoadTime(),
                is(ClientOptions.DEFAULT_INITIAL_LOAD_TIME));
        assertThat(job.getParameters().getPageLoadTime(), is(ClientOptions.DEFAULT_PAGE_LOAD_TIME));
        assertThat(job.getParameters().getShutdownTime(), is(ClientOptions.DEFAULT_SHUTDOWN_TIME));
    }

    @Test
    void shouldSetParameters() {
        // Given
        ClientSpiderJob job = new ClientSpiderJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
                parameters:
                  context:          testContext
                  user:             testUser
                  url:              https://www.example.com/test/
                  maxDuration:      20
                  maxCrawlDepth:    8
                  maxChildren:      9
                  numberOfBrowsers: 11
                  browserId:        testBrowser
                  initialLoadTime:  12
                  pageLoadTime:     13
                  shutdownTime:     14
                """;
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getParameters().getContext(), is(equalTo("testContext")));
        assertThat(job.getParameters().getUser(), is(equalTo("testUser")));
        assertThat(job.getParameters().getUrl(), is(equalTo("https://www.example.com/test/")));
        assertThat(job.getParameters().getMaxDuration(), is(equalTo(20)));
        assertThat(job.getParameters().getMaxCrawlDepth(), is(equalTo(8)));
        assertThat(job.getParameters().getMaxChildren(), is(equalTo(9)));
        assertThat(job.getParameters().getNumberOfBrowsers(), is(equalTo(11)));
        assertThat(job.getParameters().getBrowserId(), is(equalTo("testBrowser")));
        assertThat(job.getParameters().getInitialLoadTime(), is(equalTo(12)));
        assertThat(job.getParameters().getPageLoadTime(), is(equalTo(13)));
        assertThat(job.getParameters().getShutdownTime(), is(equalTo(14)));
    }

    @Test
    void shouldRunValidJob() throws URIException, NullPointerException {
        // Given
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        ContextWrapper contextWrapper = mock(ContextWrapper.class);
        given(contextWrapper.getContext()).willReturn(context);
        String url = "http://example.com";
        given(contextWrapper.getUrls()).willReturn(List.of(url));

        ClientSpider clientSpider = mock(ClientSpider.class);
        given(extClient.startScan(any(), any(), any(), any(), anyBoolean())).willReturn(1);
        given(extClient.getScan(anyInt())).willReturn(clientSpider);

        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(url)).willReturn(url);
        given(env.getDefaultContextWrapper()).willReturn(contextWrapper);

        ClientSpiderJob job = new ClientSpiderJob();

        // When
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }

    private static void assertDefaultJob(ClientSpiderJob job) {
        assertThat(job.getType(), is(equalTo("spiderClient")));
        assertThat(job.getName(), is(equalTo("spiderClient")));
        assertThat(job.getOrder(), is(equalTo(Order.LAST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }
}
