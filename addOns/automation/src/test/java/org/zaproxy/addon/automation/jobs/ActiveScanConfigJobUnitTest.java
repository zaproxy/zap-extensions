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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.jobs.ActiveScanConfigJob.InputVectors;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link ActiveScanConfigJob}. */
class ActiveScanConfigJobUnitTest extends TestUtils {

    private ScannerParam param;
    private ExtensionActiveScan ascan;

    private ActiveScanConfigJob job;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAutomation());

        param = mock(ScannerParam.class, withSettings().strictness(Strictness.LENIENT));
        ascan =
                new ExtensionActiveScan() {
                    @Override
                    protected ScannerParam getScannerParam() {
                        return param;
                    }
                };

        job = new ActiveScanConfigJob(ascan);
    }

    @Test
    void shouldReturnDefaultFields() {
        assertThat(job.getType(), is(equalTo("activeScan-config")));
        assertThat(job.getName(), is(equalTo("activeScan-config")));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.CONFIGS)));
        assertValidTemplate(job.getTemplateDataMin());
        assertValidTemplate(job.getTemplateDataMax());
        assertThat(job.getParamMethodObject(), is(equalTo(ascan)));
        assertThat(job.getParamMethodName(), is(equalTo("getScannerParam")));
    }

    @Test
    void shouldReturnNoCustomConfigParams() {
        // Given / When
        Map<String, String> params = job.getCustomConfigParameters();
        // Then
        assertThat(params, is(anEmptyMap()));
    }

    @Test
    void shouldVerifyAndApplyParamters() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        int maxRuleDurationInMins = 1;
        int maxScanDurationInMins = 2;
        int maxAlertsPerRule = 3;
        String defaultPolicy = "Policy";
        boolean handleAntiCsrfTokens = false;
        boolean injectScanRuleIdInHeader = true;
        int threadPerHost = 4;
        String yamlStr =
                "parameters:\n"
                        + "  maxRuleDurationInMins: "
                        + maxRuleDurationInMins
                        + "\n"
                        + "  maxScanDurationInMins: "
                        + maxScanDurationInMins
                        + "\n"
                        + "  maxAlertsPerRule: "
                        + maxAlertsPerRule
                        + "\n"
                        + "  defaultPolicy: "
                        + defaultPolicy
                        + "\n"
                        + "  handleAntiCSRFTokens: "
                        + handleAntiCsrfTokens
                        + "\n"
                        + "  injectPluginIdInHeader: "
                        + injectScanRuleIdInHeader
                        + "\n"
                        + "  threadPerHost: "
                        + threadPerHost
                        + "\n";
        Object data = new Yaml().load(yamlStr);

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any()))
                .willAnswer(invocation -> invocation.getArguments()[0].toString());
        job.setEnv(env);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));

        assertThat(
                job.getParameters().getMaxRuleDurationInMins(), is(equalTo(maxRuleDurationInMins)));
        verify(param).setMaxRuleDurationInMins(maxRuleDurationInMins);

        assertThat(
                job.getParameters().getMaxScanDurationInMins(), is(equalTo(maxScanDurationInMins)));
        verify(param).setMaxScanDurationInMins(maxScanDurationInMins);

        assertThat(job.getParameters().getMaxAlertsPerRule(), is(equalTo(maxAlertsPerRule)));
        verify(param).setMaxAlertsPerRule(maxAlertsPerRule);

        assertThat(job.getParameters().getDefaultPolicy(), is(equalTo(defaultPolicy)));
        verify(param).setDefaultPolicy(defaultPolicy);

        assertThat(
                job.getParameters().getHandleAntiCSRFTokens(), is(equalTo(handleAntiCsrfTokens)));
        verify(param).setHandleAntiCSRFTokens(handleAntiCsrfTokens);

        assertThat(
                job.getParameters().getInjectPluginIdInHeader(),
                is(equalTo(injectScanRuleIdInHeader)));
        verify(param).setInjectPluginIdInHeader(injectScanRuleIdInHeader);

        assertThat(job.getParameters().getThreadPerHost(), is(equalTo(threadPerHost)));
        verify(param).setThreadPerHost(threadPerHost);

        verify(param).setTargetParamsInjectable(ScannerParam.TARGET_INJECTABLE_DEFAULT);
        verify(param).setTargetParamsEnabledRPC(ScannerParam.TARGET_ENABLED_RPC_DEFAULT);
    }

    @Test
    void shouldVerifyAndApplyInputVectors() {
        // Given
        AutomationProgress progress = new AutomationProgress();
        boolean urlQueryStringEnabled = false;
        boolean addParam = true;
        boolean odata = false;
        boolean postDataEnabled = false;
        boolean multiPartFormData = false;
        boolean xml = false;
        boolean jsonEnabled = false;
        boolean scanNullValues = true;
        boolean googleWebToolkit = true;
        boolean directWebRemoting = true;
        boolean urlPath = true;
        boolean httpHeadersEnabled = true;
        boolean scanAllRequests = true;
        boolean cookieEnabled = true;
        boolean encodeCookieValues = true;
        boolean scripts = false;
        String yamlStr =
                "inputVectors:"
                        + "\n"
                        + "  urlQueryStringAndDataDrivenNodes:"
                        + "\n"
                        + "     enabled: "
                        + urlQueryStringEnabled
                        + "\n"
                        + "     addParam: "
                        + addParam
                        + "\n"
                        + "     odata: "
                        + odata
                        + "\n"
                        + "  postData:"
                        + "\n"
                        + "    enabled: "
                        + postDataEnabled
                        + "\n"
                        + "    multiPartFormData: "
                        + multiPartFormData
                        + "\n"
                        + "    xml: "
                        + xml
                        + "\n"
                        + "    json:"
                        + "\n"
                        + "      enabled: "
                        + jsonEnabled
                        + "\n"
                        + "      scanNullValues: "
                        + scanNullValues
                        + "\n"
                        + "    googleWebToolkit: "
                        + googleWebToolkit
                        + "\n"
                        + "    directWebRemoting: "
                        + directWebRemoting
                        + "\n"
                        + "  urlPath: "
                        + urlPath
                        + "\n"
                        + "  httpHeaders:"
                        + "\n"
                        + "    enabled: "
                        + httpHeadersEnabled
                        + "\n"
                        + "    allRequests: "
                        + scanAllRequests
                        + "\n"
                        + "  cookieData:"
                        + "\n"
                        + "    enabled: "
                        + cookieEnabled
                        + "\n"
                        + "    encodeCookieValues: "
                        + encodeCookieValues
                        + "\n"
                        + "  scripts: "
                        + scripts;
        Object data = new Yaml().load(yamlStr);

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        given(env.replaceVars(any()))
                .willAnswer(invocation -> invocation.getArguments()[0].toString());
        job.setEnv(env);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.applyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));

        InputVectors iv = job.getData().getInputVectors();
        assertThat(
                iv.getUrlQueryStringAndDataDrivenNodes().isEnabled(),
                is(equalTo(urlQueryStringEnabled)));
        assertThat(iv.getUrlQueryStringAndDataDrivenNodes().isAddParam(), is(equalTo(addParam)));
        verify(param).setAddQueryParam(addParam);
        assertThat(iv.getUrlQueryStringAndDataDrivenNodes().isOdata(), is(equalTo(odata)));

        assertThat(iv.getPostData().isEnabled(), is(equalTo(postDataEnabled)));
        assertThat(iv.getPostData().isMultiPartFormData(), is(equalTo(multiPartFormData)));
        assertThat(iv.getPostData().isXml(), is(equalTo(xml)));
        assertThat(iv.getPostData().getJson().isEnabled(), is(equalTo(jsonEnabled)));
        assertThat(iv.getPostData().getJson().isScanNullValues(), is(equalTo(scanNullValues)));
        verify(param).setScanNullJsonValues(scanNullValues);
        assertThat(iv.getPostData().isGoogleWebToolkit(), is(equalTo(googleWebToolkit)));
        assertThat(iv.getPostData().isDirectWebRemoting(), is(equalTo(directWebRemoting)));

        assertThat(iv.isUrlPath(), is(equalTo(urlPath)));

        assertThat(iv.getHttpHeaders().isEnabled(), is(equalTo(httpHeadersEnabled)));
        assertThat(iv.getHttpHeaders().isAllRequests(), is(equalTo(scanAllRequests)));
        verify(param).setScanHeadersAllRequests(scanAllRequests);

        assertThat(iv.getCookieData().isEnabled(), is(equalTo(cookieEnabled)));
        assertThat(iv.getCookieData().isEncodeCookieValues(), is(equalTo(encodeCookieValues)));
        verify(param).setEncodeCookieValues(encodeCookieValues);

        verify(param).setTargetParamsInjectable(60);
        verify(param).setTargetParamsEnabledRPC(40);
    }

    @Test
    void shouldVerifyAndApplyExcludes() throws Exception {
        // Given
        Session session = mock(Session.class);
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        given(model.getSession()).willReturn(session);

        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
        		excludePaths:
        		- http://www.example\\..*
        		- .*\\.abc
        		""";
        Object data = new Yaml().load(yamlStr);

        AutomationEnvironment env = mock(AutomationEnvironment.class);
        env.create(session, progress);

        job.setEnv(env);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));

        ArgumentCaptor<List<String>> result = ArgumentCaptor.captor();
        verify(session).setExcludeFromScanRegexs(result.capture());
        assertThat(result.getValue(), contains("http://www.example\\..*", ".*\\.abc"));
    }

    @Test
    void shouldErrorOnBadExcludesRegex() throws Exception {
        // Given
        AutomationProgress progress = new AutomationProgress();
        String yamlStr =
                """
        		excludePaths:
        		- http://www.example\\..*
        		- '*'
        		""";
        Object data = new Yaml().load(yamlStr);

        AutomationEnvironment env = mock(AutomationEnvironment.class);

        job.setEnv(env);
        job.setJobData(((LinkedHashMap<?, ?>) data));

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                containsString(
                        "Invalid regex: * for key excludePaths : Dangling meta character '*' near index 0"));
    }

    private static void assertValidTemplate(String value) {
        assertThat(value, is(not(equalTo(""))));
        assertDoesNotThrow(() -> new Yaml().load(value));
    }
}
