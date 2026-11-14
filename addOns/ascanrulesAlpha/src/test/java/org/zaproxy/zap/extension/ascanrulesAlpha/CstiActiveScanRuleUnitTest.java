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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector;
import org.zaproxy.zap.extension.ascanrulesAlpha.scripts.ClientSideEngineDetector.DetectionResult;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.utils.I18N;

class CstiActiveScanRuleUnitTest {

    @BeforeAll
    static void setUpMessages() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Constant.messages.addMessageBundle(
                "ascanalpha",
                ResourceBundle.getBundle(
                        "org.zaproxy.zap.extension.ascanrulesAlpha.resources.Messages",
                        Locale.ENGLISH));
    }

    @Test
    void shouldDetectAngularWhenGlobalIsPresent() {
        // Given
        TestWebDriver driver = mock(TestWebDriver.class);
        given(driver.executeScript(anyString(), any())).willReturn(Boolean.TRUE);

        // When
        DetectionResult result =
                ClientSideEngineDetector.detect(driver, "http://example.test/?q={{7*7}}");

        // Then
        assertThat(result.detected(), is(equalTo(true)));
        assertThat(result.engineName(), is(equalTo("angular")));
        assertThat(result.globalExpression(), is(equalTo("angular.version")));
    }

    @Test
    void shouldReturnUnknownIfNavigationFails() {
        // Given
        TestWebDriver driver = mock(TestWebDriver.class);
        willThrow(new RuntimeException("navigation failed")).given(driver).get(anyString());

        // When
        DetectionResult result =
                ClientSideEngineDetector.detect(driver, "http://example.test/fail");

        // Then
        assertThat(result.detected(), is(equalTo(false)));
        assertThat(result.engineName(), is(equalTo("unknown")));
        verify(driver, never()).executeScript(anyString(), any());
    }

    @Test
    void shouldReturnUnknownWhenNoEngineIsDetected() {
        // Given
        TestWebDriver driver = mock(TestWebDriver.class);
        given(driver.executeScript(anyString(), any())).willReturn(Boolean.FALSE);

        // When
        DetectionResult result =
                ClientSideEngineDetector.detect(driver, "http://example.test/no-engine");

        // Then
        assertThat(result.detected(), is(equalTo(false)));
        assertThat(result.engineName(), is(equalTo("unknown")));
        assertThat(result.globalExpression(), is(equalTo("")));
    }

    @Test
    void shouldContinueChecksAfterScriptException() {
        // Given
        TestWebDriver driver = mock(TestWebDriver.class);
        AtomicInteger calls = new AtomicInteger(0);
        given(driver.executeScript(anyString(), any()))
                .willAnswer(
                        invocation -> {
                            String payload = invocation.getArgument(0, String.class);
                            if (payload.contains("__zapCstiWaitState")) {
                                return Boolean.TRUE;
                            }
                            if (calls.getAndIncrement() == 0) {
                                throw new RuntimeException("first engine check failed");
                            }
                            return Boolean.TRUE;
                        });

        // When
        DetectionResult result =
                ClientSideEngineDetector.detect(driver, "http://example.test/continue");

        // Then
        assertThat(result.detected(), is(equalTo(true)));
        assertThat(result.engineName(), is(equalTo("vue")));
        assertThat(result.globalExpression(), is(equalTo("Vue")));
    }

    @Test
    void shouldCaptureFunctionCallHeuristicMatches() {
        // Given
        TestWebDriver driver = mock(TestWebDriver.class);
        given(driver.executeScript(anyString()))
                .willAnswer(
                        invocation -> {
                            String payload = invocation.getArgument(0, String.class);
                            if (payload.contains(
                                    "document.querySelectorAll('script:not([src])')")) {
                                return "{\"script\":\"angular.module('app',[]).controller('C', function(){});\","
                                        + "\"html\":\"<html ng-app='app'></html>\"}";
                            }
                            return Boolean.FALSE;
                        });
        given(driver.executeScript(anyString(), any()))
                .willAnswer(
                        invocation -> {
                            String payload = invocation.getArgument(0, String.class);

                            if (payload.contains("String(arguments[0]).split('.')")) {
                                Object arg = invocation.getArgument(1);
                                String global = null;
                                if (arg instanceof Object[] varArgs && varArgs.length > 0) {
                                    global = String.valueOf(varArgs[0]);
                                } else if (arg != null) {
                                    global = String.valueOf(arg);
                                }
                                if ("angular.version".equals(global)) {
                                    return Boolean.TRUE;
                                }
                                return Boolean.FALSE;
                            }

                            return Boolean.FALSE;
                        });

        // When
        DetectionResult result =
                ClientSideEngineDetector.detect(driver, "http://example.test/heuristic");

        // Then
        assertThat(result.detected(), is(equalTo(true)));
        assertThat(result.engineName(), is(equalTo("angular")));
        assertThat(result.globalExpression(), is(equalTo("angular.version")));
        assertThat(result.hasActiveCalls(), is(equalTo(true)));
        assertThat(result.matchedCalls(), containsInAnyOrder(".controller("));
    }

    @Test
    void shouldScoreLowWhenOnlyGlobalDetected() {
        DetectionResult result = new DetectionResult("angular", "angular.version");

        assertThat(
                CstiActiveScanRule.scoreEngineDetectionConfidence(result),
                is(equalTo(CstiActiveScanRule.EngineConfidence.LOW)));
    }

    @Test
    void shouldScoreHighForGlobalAndActivityWhenTagHeuristicApplies() {
        DetectionResult result =
                new DetectionResult("angular", "angular.version", List.of(".controller("));

        assertThat(
                CstiActiveScanRule.scoreEngineDetectionConfidence(result),
                is(equalTo(CstiActiveScanRule.EngineConfidence.HIGH)));
    }

    @Test
    void shouldScoreVeryHighForGlobalAndTagEvidence() {
        DetectionResult result =
                new DetectionResult(
                        "angular", "angular.version", List.of(), List.of(), List.of("ng-app"));

        assertThat(
                CstiActiveScanRule.scoreEngineDetectionConfidence(result),
                is(equalTo(CstiActiveScanRule.EngineConfidence.VERY_HIGH)));
    }

    @Test
    void shouldScoreVeryHighForGlobalAndActivityWhenTagHeuristicIsNotApplicable() {
        DetectionResult result = new DetectionResult("regular", "Regular", List.of("new Regular("));

        assertThat(
                CstiActiveScanRule.scoreEngineDetectionConfidence(result),
                is(equalTo(CstiActiveScanRule.EngineConfidence.VERY_HIGH)));
    }

    @Test
    void shouldNotReportConfidenceWhenNoEngineIsDetected() {
        DetectionResult result = new DetectionResult("unknown", "");

        String report =
                CstiActiveScanRule.buildEngineDetectionReport(
                        List.of("Input [id=q]"),
                        List.of(),
                        result,
                        CstiActiveScanRule.EngineConfidence.LOW);

        assertThat(report, containsString("Engine : not detected via JS global check"));
        assertThat(report, not(containsString("Detection confidence")));
    }

    @Test
    void shouldStripQueryAndFragmentFromUrl() {
        // Given
        CstiActiveScanRule rule = new CstiActiveScanRule();

        // When
        String stripped = rule.stripQueryAndFragment("https://example.test/path?a=1#frag");

        // Then
        assertThat(stripped, is(equalTo("https://example.test/path")));
    }

    @Test
    void shouldResolveSupportedBrowserId() {
        // Given
        CstiActiveScanRule rule = new CstiActiveScanRule();

        // When
        Browser resolved = rule.resolvePreferredBrowser(Browser.CHROME_HEADLESS.getId());

        // Then
        assertThat(resolved, is(equalTo(Browser.CHROME_HEADLESS)));
    }

    @Test
    void shouldDefaultWhenBrowserIdIsUnknown() {
        // Given
        CstiActiveScanRule rule = new CstiActiveScanRule();

        // When
        Browser resolved = rule.resolvePreferredBrowser("not-a-browser");

        // Then
        assertThat(resolved, is(equalTo(Browser.FIREFOX_HEADLESS)));
    }

    @Test
    void shouldDefaultWhenBrowserIdIsUnsupported() {
        // Given
        CstiActiveScanRule rule = new CstiActiveScanRule();

        // When
        Browser resolved = rule.resolvePreferredBrowser(Browser.HTML_UNIT.getId());

        // Then
        assertThat(resolved, is(equalTo(Browser.FIREFOX_HEADLESS)));
    }

    @Test
    void shouldProvidePayloadProfileForAngular() {
        ClientSideEngineDetector.PayloadDefinition payload =
                ClientSideEngineDetector.getPayloadDefinition("angular");

        assertThat(payload, is(notNullValue()));
        assertThat(payload.payload(), is(equalTo("{{11111*11111}}")));
        assertThat(payload.expectedResult(), is(equalTo("123454321")));
    }

    @Test
    void shouldProvidePayloadProfileForArtTemplate() {
        ClientSideEngineDetector.PayloadDefinition payload =
                ClientSideEngineDetector.getPayloadDefinition("art-template");

        assertThat(payload, is(notNullValue()));
        assertThat(payload.payload(), is(equalTo("{{11111 * 11111}}")));
        assertThat(payload.expectedResult(), is(equalTo("123454321")));
    }

    @Test
    void shouldCreateUniqueOperandPayloadForMathProfiles() {
        ClientSideEngineDetector.PayloadDefinition payload =
                ClientSideEngineDetector.getPayloadDefinition("angular").withOperand(11112);

        assertThat(payload.supportsUniqueOperands(), is(equalTo(true)));
        assertThat(payload.payload(), is(equalTo("{{11112*11112}}")));
        assertThat(payload.expectedResult(), is(equalTo("123476544")));
    }

    @Test
    void shouldProvidePayloadProfileForEveryDetectedTemplateEngine() {
        for (String engine :
                List.of(
                        "angular",
                        "vue",
                        "mavo",
                        "handlebars",
                        "regular",
                        "template7",
                        "ejs",
                        "marko",
                        "tmpl",
                        "ember",
                        "jsrender",
                        "dot",
                        "art-template",
                        "tempo",
                        "transparency",
                        "svelte",
                        "underscore",
                        "lit",
                        "mustache",
                        "hogan",
                        "twig",
                        "markup",
                        "dust",
                        "nunjucks",
                        "pug",
                        "loadTemplate",
                        "pure",
                        "squirrelly",
                        "swig",
                        "icanhaz",
                        "micro-template",
                        "juicer",
                        "alpine")) {
            assertThat(
                    engine,
                    ClientSideEngineDetector.getPayloadDefinition(engine),
                    is(notNullValue()));
        }
    }

    @Test
    void shouldProvideObjectPayloadProfileForHandlebars() {
        ClientSideEngineDetector.PayloadDefinition payload =
                ClientSideEngineDetector.getPayloadDefinition("handlebars");

        assertThat(payload, is(notNullValue()));
        assertThat(payload.payload(), is(equalTo("{{this}}")));
        assertThat(payload.expectedResult(), is(equalTo("[object Object]")));
        assertThat(payload.supportsUniqueOperands(), is(equalTo(false)));
    }

    @Test
    void shouldProvideObjectPayloadProfileForMustache() {
        ClientSideEngineDetector.PayloadDefinition payload =
                ClientSideEngineDetector.getPayloadDefinition("mustache");

        assertThat(payload, is(notNullValue()));
        assertThat(payload.payload(), is(equalTo("{{this}}")));
        assertThat(payload.expectedResult(), is(equalTo("[object Object]")));
    }

    @Test
    void shouldProvideObjectPayloadProfilesForNonMathEngines() {
        for (String engine :
                List.of("handlebars", "tempo", "mustache", "markup", "dust", "loadTemplate")) {
            ClientSideEngineDetector.PayloadDefinition payload =
                    ClientSideEngineDetector.getPayloadDefinition(engine);

            assertThat(payload, is(notNullValue()));
            assertThat(payload.expectedResult(), is(equalTo("[object Object]")));
        }
    }

    @Test
    void shouldReplaceMatchingQueryParameterOnly() {
        String replaced =
                CstiActiveScanRule.replaceParameterValue(
                        "https://example.test/search?q=old&page=2#frag", "q", "{{11111*11111}}");

        assertThat(
                replaced,
                is(equalTo("https://example.test/search?q=%7B%7B11111*11111%7D%7D&page=2#frag")));
    }

    private interface TestWebDriver extends WebDriver, JavascriptExecutor {}
}
