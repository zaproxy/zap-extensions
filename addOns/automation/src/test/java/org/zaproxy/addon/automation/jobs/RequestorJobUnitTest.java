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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.utils.I18N;

class RequestorJobUnitTest {
    private ExtensionLoader extensionLoader;
    private ExtensionHistory extHistory;

    private HttpSender httpSender;

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);

        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extHistory = new ExtensionHistory();
        given(extensionLoader.getExtension(ExtensionHistory.class)).willReturn(extHistory);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        httpSender = mock(HttpSender.class);
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        RequestorJob job = new RequestorJob();

        // Then
        assertThat(job.getType(), is(equalTo("requestor")));
        assertThat(job.getName(), is(equalTo("requestor")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.FIRST_EXPLORE)));
        assertThat(job.getParamMethodObject(), is(equalTo(null)));
        assertThat(job.getParamMethodName(), is(equalTo(null)));
    }

    @Test
    void shouldReturnNoCustomConfigParams() {
        // Given
        RequestorJob job = new RequestorJob();

        // When
        Map<String, String> params = job.getCustomConfigParameters();

        // Then
        assertThat(params.size(), is(equalTo(0)));
    }

    @Test
    void shouldFailIfBadRequestList() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        LinkedHashMap<String, String> jobData = new LinkedHashMap<>();
        jobData.put("requests", "Incorrect");

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("!automation.error.requestor.badlist!")));
    }

    @Test
    void shouldFailIfMissingUrl() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        String yamlStr = "requests:\n" + "- method: GET\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.requestor.badurl!")));
    }

    @Test
    void shouldFailIfBadRequestUrl() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        String yamlStr = "requests:\n" + "- url: Not a url\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.requestor.badurl!")));
    }

    @Test
    void shouldDefaultMethodToGetIfNull() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr = "requests:\n" + "- url: https://www.example.com\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(
                msg.getRequestHeader().getURI().toString(), is(equalTo("https://www.example.com")));
        assertThat(msg.getRequestHeader().getMethod(), is(equalTo("GET")));
    }

    @Test
    void shouldDefaultMethodToGetIfEmpty() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr = "requests:\n" + "- url: https://www.example.com\n" + "  method: \n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(
                msg.getRequestHeader().getURI().toString(), is(equalTo("https://www.example.com")));
        assertThat(msg.getRequestHeader().getMethod(), is(equalTo("GET")));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", HttpHeader.HTTP10, HttpHeader.HTTP11, "HTTP/2"})
    void shouldBeValidHttpVersion(String httpVersion) {
        // Given / When
        boolean valid = RequestorJob.isValidHttpVersion(httpVersion);
        // Then
        assertThat(valid, is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"HTP/1.1", "HTTP/a"})
    void shouldBeInvalidHttpVersion(String httpVersion) {
        // Given / When
        boolean valid = RequestorJob.isValidHttpVersion(httpVersion);
        // Then
        assertThat(valid, is(equalTo(false)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = "   ")
    void shouldUseDefaultHttpVersion(String httpVersion) throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr = "requests:\n" + "- url: https://www.example.com\n";
        if (httpVersion != null) {
            yamlStr += "  httpVersion: \"" + httpVersion + "\"\n";
        }
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getVersion(), is(equalTo(HttpHeader.HTTP11)));
    }

    @ParameterizedTest
    @ValueSource(strings = {HttpHeader.HTTP10, HttpHeader.HTTP11, "HTTP/2"})
    void shouldUseProvidedHttpVersion(String httpVersion) throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  httpVersion: "
                        + httpVersion
                        + "\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getVersion(), is(equalTo(httpVersion)));
    }

    @Test
    void shouldErrorIfInvalidHttpVersion() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        String yamlStr =
                "requests:\n" + "- url: https://www.example.com\n" + "  httpVersion: HT/1.a\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors(), hasSize(1));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("!automation.error.requestor.httpversion!")));
    }

    @Test
    void shouldErrorIfInvalidResponseCode() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseCode: Not an int\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badint!")));
    }

    @Test
    void shouldWarnIfUnexpectedResponseCode() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        RequestorJob job = new RequestorJob();

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseCode: 999\n";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.requestor.badcode!")));
    }

    @Test
    void shouldNotWarnIfCodeMatches() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseCode: 200";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        doAnswer(
                        invocation -> {
                            Object[] args = invocation.getArguments();
                            ((HttpMessage) args[0]).getResponseHeader().setStatusCode(200);
                            return null;
                        })
                .when(httpSender)
                .sendAndReceive(any());

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldWarnIfCodeMismatch() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  method: GET\n"
                        + "  responseCode: 200";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        doAnswer(
                        invocation -> {
                            Object[] args = invocation.getArguments();
                            ((HttpMessage) args[0]).getResponseHeader().setStatusCode(404);
                            return null;
                        })
                .when(httpSender)
                .sendAndReceive(any());

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("!automation.error.requestor.codemismatch!")));
    }

    @Test
    void shouldSendMessageWithSetValues() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  method: POST\n"
                        + "  data: aaa=bbb&ccc=ddd";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(
                msg.getRequestHeader().getURI().toString(), is(equalTo("https://www.example.com")));
        assertThat(msg.getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(msg.getRequestBody().toString(), is(equalTo("aaa=bbb&ccc=ddd")));
    }

    @Test
    void shouldSendHeadersWithSetValues() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  headers:\n"
                        + "    - 'header1:value1'\n"
                        + "    - 'header2:value2'\n"
                        + "    - 'header3:'";

        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getHeader("header1"), is(equalTo("value1")));
        assertThat(msg.getRequestHeader().getHeader("header2"), is(equalTo("value2")));
        assertThat(msg.getRequestHeader().getHeader("header3"), is(equalTo("")));
    }

    @Test
    void shouldSendHeaderWithEmptyStringValue() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  headers:\n"
                        + "    - 'header1:'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getHeader("header1"), is(equalTo("")));
    }

    @Test
    void shouldAcceptEmptyHeadersList() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr = "requests:\n" + "- url: https://www.example.com\n" + "  headers: []";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldMaintainOrderOfHeadersWhileSending() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  headers:\n"
                        + "   - 'header1:value1'\n"
                        + "   - 'header2:value2'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getHeaders().get(0).getName(), is(equalTo("header1")));
        assertThat(msg.getRequestHeader().getHeaders().get(1).getName(), is(equalTo("header2")));
    }

    @Test
    void shouldSendHeadersWithSameName() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://www.example.com\n"
                        + "  headers:\n"
                        + "   - 'header1:value1'\n"
                        + "   - 'header1:value1'";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(msg.getRequestHeader().getHeaders().get(0).getName(), is(equalTo("header1")));
        assertThat(msg.getRequestHeader().getHeaders().get(1).getName(), is(equalTo("header1")));
    }

    @Test
    void shouldHandleUrlsWithEnvVarValues() throws IOException {
        // Given
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        RequestorJob job = new RequestorJob(httpSender);

        String yamlStr =
                "requests:\n"
                        + "- url: https://${urlvar}\n"
                        + "  method: POST\n"
                        + "  data: aaa=bbb&ccc=${postvar}";
        Yaml yaml = new Yaml();
        LinkedHashMap<?, ?> jobData = (LinkedHashMap<?, ?>) yaml.load(yamlStr);

        // When
        env.getData().getVars().put("urlvar", "www.example.com");
        env.getData().getVars().put("postvar", "xxx");
        job.setJobData(jobData);
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        HttpMessage msg = getMessagesSent(1).get(0);
        assertThat(
                msg.getRequestHeader().getURI().toString(), is(equalTo("https://www.example.com")));
        assertThat(msg.getRequestHeader().getMethod(), is(equalTo("POST")));
        assertThat(msg.getRequestBody().toString(), is(equalTo("aaa=bbb&ccc=xxx")));
    }

    private List<HttpMessage> getMessagesSent(int number) throws IOException {
        ArgumentCaptor<HttpMessage> argument = ArgumentCaptor.forClass(HttpMessage.class);
        verify(httpSender, times(number)).sendAndReceive(argument.capture());
        return argument.getAllValues();
    }
}
