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
package org.zaproxy.addon.authhelper.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.utils.I18N;

class AiAuthScriptGeneratorUnitTest {

    private static final String USERNAME = "realUser";
    private static final String PASSWORD = "realS3cret";

    private AiAssistedAuthenticationMethod config;
    private LlmCommunicationService llm;
    private AiAuthScriptGenerator generator;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
    }

    @BeforeEach
    void setUp() {
        config = new AiAssistedAuthenticationMethodType().createAuthenticationMethod(0);
        config.setLoginPageUrl("http://localhost/login");
        llm = mock(LlmCommunicationService.class);
        generator = new AiAuthScriptGenerator(config, llm, null);
    }

    private static AiAuthInputElement element(String type, String value) {
        return new AiAuthInputElement(
                "input", type, "id", "name", "label", "placeholder", value, null, true);
    }

    /**
     * Stubs {@code llm.chat(...)} to return a response whose {@code aiMessage().text()} is json.
     */
    private void stubLlmResponse(String json) throws Exception {
        ChatResponse response = mock(ChatResponse.class);
        AiMessage aiMessage = mock(AiMessage.class);
        given(response.aiMessage()).willReturn(aiMessage);
        given(aiMessage.text()).willReturn(json);
        given(llm.chat(any(ChatRequest.class))).willReturn(response);
    }

    @Nested
    class MaskCredentialValues {

        @Test
        void shouldMaskFilledPasswordTypeField() {
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("password", PASSWORD)), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldNotMaskEmptyPasswordTypeField() {
            // An empty password field must stay empty, so the LLM can tell it still needs filling
            // in rather than believing it already contains a (masked) value.
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("password", "")), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), is(equalTo("")));
        }

        @Test
        void shouldMaskTextFieldValueEqualToRealUsername() {
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("text", USERNAME)), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.USERNAME_PLACEHOLDER)));
        }

        @Test
        void shouldMaskTextFieldValueEqualToRealPassword() {
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("text", PASSWORD)), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldNotMaskUnrelatedFieldValues() {
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("text", "Project1")), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), is(equalTo("Project1")));
        }

        @Test
        void shouldNotMaskNullValues() {
            List<AiAuthInputElement> masked =
                    generator.maskCredentialValues(
                            List.of(element("text", null)), USERNAME, PASSWORD);

            assertThat(masked.get(0).value(), nullValue());
        }
    }

    @Nested
    class ExecuteAction {

        private TestWebDriver wd;
        private WebElement webElement;

        @BeforeEach
        void setUpDriver() {
            wd = mock(TestWebDriver.class);
            webElement = mock(WebElement.class);
        }

        @Test
        void shouldClickResolvedElement() {
            when(wd.findElements(By.cssSelector("#submit"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.CLICK, List.of("#submit"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            verify(webElement).click();
            assertThat(result.success(), is(true));
            assertThat(result.usedSelector(), is(equalTo("#submit")));
        }

        @Test
        void shouldFailWhenNoElementMatchesAnySelector() {
            when(wd.findElements(By.cssSelector("#missing"))).thenReturn(List.of());
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.CLICK, List.of("#missing"), null);

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldSendRealCredentialButKeepPlaceholderInResult() {
            when(wd.findElements(By.cssSelector("#password"))).thenReturn(List.of(webElement));
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.SEND_KEYS,
                            List.of("#password"),
                            AiAuthTurnPayload.PASSWORD_PLACEHOLDER);

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            verify(webElement).sendKeys(PASSWORD);
            assertThat(result.success(), is(true));
            assertThat(result.value(), is(equalTo(AiAuthTurnPayload.PASSWORD_PLACEHOLDER)));
        }

        @Test
        void shouldFailSelectWhenOptionNotFound() {
            when(wd.findElements(By.cssSelector("#domain"))).thenReturn(List.of(webElement));
            when(webElement.getTagName()).thenReturn("select");
            when(webElement.getAttribute("multiple")).thenReturn(null);
            when(webElement.findElements(any())).thenReturn(List.of());
            AiAuthAction action =
                    new AiAuthAction(AiAuthActionType.SELECT, List.of("#domain"), "Project1");

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldWaitForGivenSeconds() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "0");

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(true));
        }

        @Test
        void shouldFailOnInvalidWaitValue() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "not-a-number");

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldWaitForMaxAllowedSeconds() {
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT,
                            null,
                            String.valueOf(AiAuthScriptGenerator.MAX_WAIT_SECONDS));

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(true));
        }

        @Test
        void shouldFailWhenWaitExceedsMaxAllowedSeconds() {
            // A model-controlled WAIT value must be bounded, otherwise a response like
            // Integer.MAX_VALUE would block the auth worker thread for decades.
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT,
                            null,
                            String.valueOf(AiAuthScriptGenerator.MAX_WAIT_SECONDS + 1));

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldFailWhenWaitIsExtremelyLarge() {
            AiAuthAction action =
                    new AiAuthAction(
                            AiAuthActionType.WAIT, null, String.valueOf(Integer.MAX_VALUE));

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldFailWhenWaitIsNegative() {
            AiAuthAction action = new AiAuthAction(AiAuthActionType.WAIT, null, "-1");

            AiAuthActionResult result = generator.executeAction(wd, action, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }
    }

    @Nested
    class Run {

        private TestWebDriver wd;

        @BeforeEach
        void setUpDriver() {
            wd = mock(TestWebDriver.class);
            when(wd.executeScript(AiAuthScriptGenerator.PAGE_ELEMENTS_JS)).thenReturn("[]");
            when(wd.executeScript(AiAuthScriptGenerator.PAGE_TEXT_JS)).thenReturn("");
            when(wd.getCurrentUrl()).thenReturn("http://localhost/login");
            when(wd.getTitle()).thenReturn("Login");
        }

        @Test
        void shouldReturnFailureWhenLlmReturnsNoParseableResponse() throws Exception {
            given(llm.chat(any(ChatRequest.class))).willThrow(new RuntimeException("boom"));

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
        }

        @Test
        void shouldReportRawResponseToChatTabWhenNotParseable() throws Exception {
            given(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.error.unparseable",
                                    "this is not json"))
                    .willReturn("Unparseable LLM response: this is not json");
            LlmChatTabPanel chatTab = mock(LlmChatTabPanel.class);
            AiAuthScriptGenerator withChatTab = new AiAuthScriptGenerator(config, llm, chatTab);
            stubLlmResponse("this is not json");

            withChatTab.run(wd, USERNAME, PASSWORD);

            verify(chatTab)
                    .appendToOutput(
                            eq(LlmChatTabPanel.ERROR_LABEL),
                            eq("Unparseable LLM response: this is not json"));
        }

        @Test
        void shouldNotThrowWhenLlmReturnsNullActionsForInProgressState() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "IN_PROGRESS", "reasoning": "thinking", "actions": null,
                      "successIndicator": null }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            // Every turn repeats the same IN_PROGRESS/null-actions response, so the loop should
            // run out its MAX_TURNS budget rather than throwing a NullPointerException.
            assertThat(result.success(), is(false));
        }

        @Test
        void shouldReturnSuccessOnTerminalSuccessState() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "SUCCESS", "reasoning": "Logged in", "actions": [],
                      "successIndicator": { "type": "URL_PATTERN", "value": "home" } }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(true));
            assertThat(result.finalState(), is(AiAuthState.SUCCESS));
        }

        @Test
        void shouldReturnFailureAfterMaxTurnsWhenStuckInProgress() throws Exception {
            stubLlmResponse(
                    """
                    { "state": "IN_PROGRESS", "reasoning": "still working", "actions": [],
                      "successIndicator": null }
                    """);

            AiAuthResult result = generator.run(wd, USERNAME, PASSWORD);

            assertThat(result.success(), is(false));
            assertThat(result.finalState(), is(AiAuthState.FAILURE));
        }
    }

    /** A WebDriver that also implements JavascriptExecutor, as ZAP's browsers always are. */
    private interface TestWebDriver extends WebDriver, JavascriptExecutor {}
}
