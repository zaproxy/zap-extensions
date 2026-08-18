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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.data.message.SystemMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.authhelper.llm.AiAssistedAuthenticationMethodType.AiAssistedAuthenticationMethod;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;

/**
 * Drives an iterative browser-based authentication flow using an LLM.
 *
 * <p>Each turn:
 *
 * <ol>
 *   <li>Extract the current page state (URL, title, visible form elements) via JavaScript.
 *   <li>Serialise the state into an {@link AiAuthTurnPayload} and send it to the LLM.
 *   <li>Deserialise the {@link AiAuthResponse} and execute any returned actions.
 *   <li>Repeat until the LLM returns a terminal state or {@link #MAX_TURNS} is reached.
 * </ol>
 *
 * <p>Credentials are passed to the LLM as placeholder tokens ({@link
 * AiAuthTurnPayload#USERNAME_PLACEHOLDER}, {@link AiAuthTurnPayload#PASSWORD_PLACEHOLDER}). Real
 * values are substituted just before executing each action so they are never sent to the LLM.
 */
public class AiAuthScriptGenerator {

    private static final Logger LOGGER = LogManager.getLogger(AiAuthScriptGenerator.class);

    static final int MAX_TURNS = 10;
    static final long PAGE_SETTLE_MS = 1500;
    static final int MAX_WAIT_SECONDS = 30;

    /**
     * JavaScript that extracts all interactive form elements from the current page and returns them
     * as a JSON string. Using a JSON string avoids Selenium's type-coercion of nested maps.
     */
    // Selenium executeScript requires a top-level `return` to capture the result value.
    // An IIFE without a top-level return causes the driver to see `undefined` and return null.
    static final String PAGE_TEXT_JS =
            """
            var parts = [];
            document.querySelectorAll('h1, h2, h3, p, a, label, span').forEach(function(el) {
              try {
                if (el.offsetParent !== null && !el.hidden) {
                  var t = el.textContent.trim().replace(/\\s+/g, ' ');
                  if (t) parts.push(t);
                }
              } catch(e) {}
            });
            var text = parts.join(' | ');
            return text.length > 500 ? text.substring(0, 500) + '...' : text;
            """;

    static final String PAGE_ELEMENTS_JS =
            """
            var els = [];
            document.querySelectorAll('input, select, textarea, button').forEach(function(el) {
              var label = null;
              if (el.type === 'hidden' || el.offsetParent === null || el.hidden) {
                return;
              }
              try {
                if (el.id) {
                  var lbl = document.querySelector('label[for="' + el.id + '"]');
                  if (lbl) label = lbl.textContent.trim();
                }
                if (!label) {
                  var parent = el.closest('label');
                  if (parent) {
                    var clone = parent.cloneNode(true);
                    clone.querySelectorAll('input,select,textarea,button').forEach(function(c){c.remove();});
                    label = clone.textContent.trim() || null;
                  }
                }
              } catch(e) {}
              var opts = null;
              if (el.tagName === 'SELECT') {
                opts = Array.from(el.options).map(function(o) { return o.text.trim(); });
              }
              els.push({
                tag: el.tagName.toLowerCase(),
                type: el.getAttribute('type') || null,
                id: el.id || null,
                name: el.name || null,
                label: label,
                placeholder: el.placeholder || null,
                value: el.value || null,
                options: opts,
                visible: el.offsetParent !== null && !el.hidden
              });
            });
            return JSON.stringify(els);
            """;

    private static final String SYSTEM_PROMPT =
            """
            You are a browser automation agent whose sole job is to complete a web authentication flow.

            You will receive a JSON object with these fields:
              step            - the current turn number (starts at 1)
              url             - the current page URL
              pageTitle       - the page <title>
              inputElements   - an array of visible form elements on the page; each has:
                                  tag, type, id, name, label, placeholder, value, options, visible
              previousActions - the actions you requested last turn and whether each succeeded
              credentials     - always {"username":"{{username}}","password":"{{password}}"}
              visibleText     - visible headings, labels and link text on the page (first 500 chars)
              userHint        - optional free-text guidance from the human operator

            You must respond with ONLY a valid JSON object matching this schema (no markdown, no code fences):
            {
              "state": "IN_PROGRESS" | "SUCCESS" | "FAILURE" | "MFA_REQUIRED" | "CAPTCHA_DETECTED",
              "reasoning": "<one sentence explaining what you observe and what you will do>",
              "actions": [
                {
                  "type": "CLICK" | "SEND_KEYS" | "SELECT" | "WAIT",
                  "selectors": ["#most-stable", ".fallback", "button[name=\\"submit\\"]"],
                  "value": "<text to type, option to select, or seconds as a string for WAIT; null for CLICK>"
                }
              ],
              "successIndicator": {
                "type": "URL_PATTERN" | "ELEMENT_APPEARS" | "ELEMENT_DISAPPEARS",
                "value": "<substring of expected URL, or CSS selector>"
              }
            }

            Rules:
            - For a username/email field use value "{{username}}". For a password field use "{{password}}".
              Never invent or guess real credential values.
            - Provide selectors from most-specific (id) to least-specific (tag/class).
            - "actions" must be [] and "successIndicator" must be non-null when state is SUCCESS.
            - "actions" must be [] and "successIndicator" must be null for all other terminal states.
            - Set state SUCCESS only when you are confident the browser shows a post-login page
              (URL changed away from the login page, a greeting is visible, a dashboard loaded, etc.).
            - Set state FAILURE if credentials are rejected or a dead end is reached.
            - Follow any instructions in the userHint field — they describe non-obvious steps
              (e.g. "set the domain dropdown to Project1") that are required for login to succeed.
            - Respond with JSON only. Do not wrap the response in a code block.
            """;

    private final AiAssistedAuthenticationMethod config;
    private final LlmCommunicationService llm;
    private final ObjectMapper mapper;
    private final LlmChatTabPanel chatTab;
    private final List<AiAuthActionResult> successfulActions = new ArrayList<>();

    public AiAuthScriptGenerator(
            AiAssistedAuthenticationMethod config,
            LlmCommunicationService llm,
            LlmChatTabPanel chatTab) {
        this.config = config;
        this.llm = llm;
        this.mapper = new ObjectMapper();
        this.chatTab = chatTab;
    }

    /**
     * Runs the iterative authentication loop.
     *
     * @param wd an already-open WebDriver instance; navigation and closure are the caller's
     *     responsibility
     * @param username the real username to substitute for {@link
     *     AiAuthTurnPayload#USERNAME_PLACEHOLDER}
     * @param password the real password to substitute for {@link
     *     AiAuthTurnPayload#PASSWORD_PLACEHOLDER}
     * @return the final result, which may be success or any terminal failure state
     */
    public AiAuthResult run(WebDriver wd, String username, String password) {
        LOGGER.info("Starting AI auth loop for URL: {}", config.getLoginPageUrl());
        wd.get(config.getLoginPageUrl());
        waitSeconds(config.getLoginPageWait());

        List<AiAuthActionResult> previousActions = new ArrayList<>();

        for (int step = 1; step <= MAX_TURNS; step++) {
            List<AiAuthInputElement> elements =
                    maskCredentialValues(extractPageElements(wd), username, password);
            String currentUrl = wd.getCurrentUrl();
            String pageTitle = wd.getTitle();
            String visibleText = extractVisibleText(wd);
            LOGGER.debug("Turn {}: url={}, elements={}", step, currentUrl, elements.size());

            logTurnContext(step, currentUrl, pageTitle, elements, visibleText);

            AiAuthTurnPayload payload =
                    new AiAuthTurnPayload(
                            step,
                            currentUrl,
                            pageTitle,
                            elements,
                            previousActions,
                            Map.of(
                                    "username", AiAuthTurnPayload.USERNAME_PLACEHOLDER,
                                    "password", AiAuthTurnPayload.PASSWORD_PLACEHOLDER),
                            config.getHint(),
                            visibleText);

            AiAuthResponse response = askLlm(payload);
            if (response == null) {
                AiAuthResult failure =
                        AiAuthResult.failure(
                                Constant.messages.getString(
                                        "authhelper.auth.method.ai.chat.error.no.response", step));
                logFinalResult(failure);
                return failure;
            }

            LOGGER.info(
                    "Turn {}: state={}, reasoning={}",
                    step,
                    response.state(),
                    response.reasoning());
            logLlmResponse(response);

            if (response.isTerminal()) {
                boolean success = response.state() == AiAuthState.SUCCESS;
                LOGGER.info("AI auth loop finished: success={}", success);
                AiAuthResult result =
                        new AiAuthResult(
                                success,
                                response.state(),
                                response.reasoning(),
                                response.successIndicator());
                if (success) {
                    logFinalResult(result);
                }
                return result;
            }

            previousActions = new ArrayList<>();
            for (AiAuthAction action :
                    response.actions() != null ? response.actions() : List.<AiAuthAction>of()) {
                AiAuthActionResult result = executeAction(wd, action, username, password);
                LOGGER.debug(
                        "Action {}: selector={}, success={}",
                        action.type(),
                        result.usedSelector(),
                        result.success());
                if (result.success()) {
                    successfulActions.add(result);
                }
                previousActions.add(result);
            }

            waitMillis(PAGE_SETTLE_MS);
        }

        AiAuthResult maxTurns =
                AiAuthResult.failure(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.max.turns", MAX_TURNS));
        logFinalResult(maxTurns);
        return maxTurns;
    }

    /** Returns all successfully-executed actions, in order, for Zest script generation. */
    List<AiAuthActionResult> getSuccessfulActions() {
        return Collections.unmodifiableList(successfulActions);
    }

    // ─── Page extraction ──────────────────────────────────────────────────────

    List<AiAuthInputElement> extractPageElements(WebDriver wd) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) wd;
            String json = (String) js.executeScript(PAGE_ELEMENTS_JS);
            return mapper.readValue(json, new TypeReference<List<AiAuthInputElement>>() {});
        } catch (Exception e) {
            LOGGER.warn("Failed to extract page elements: {}", e.getMessage());
            return List.of();
        }
    }

    String extractVisibleText(WebDriver wd) {
        try {
            JavascriptExecutor js = (JavascriptExecutor) wd;
            String text = (String) js.executeScript(PAGE_TEXT_JS);
            return text != null ? text : "";
        } catch (Exception e) {
            LOGGER.debug("Failed to extract visible text: {}", e.getMessage());
            return "";
        }
    }

    /**
     * Replaces any real credential value found in extracted page elements with its placeholder
     * token, so a value typed via {@code SEND_KEYS} is never read back off the DOM and sent to the
     * LLM on a later turn. Leaves genuinely empty fields untouched, so the LLM can still tell that
     * they haven't been filled in yet.
     */
    List<AiAuthInputElement> maskCredentialValues(
            List<AiAuthInputElement> elements, String username, String password) {
        return elements.stream().map(e -> maskCredentialValue(e, username, password)).toList();
    }

    private AiAuthInputElement maskCredentialValue(
            AiAuthInputElement element, String username, String password) {
        String value = element.value();
        if (value == null || value.isEmpty()) {
            return element;
        }
        if ("password".equals(element.type()) || value.equals(password)) {
            return withValue(element, AiAuthTurnPayload.PASSWORD_PLACEHOLDER);
        }
        if (value.equals(username)) {
            return withValue(element, AiAuthTurnPayload.USERNAME_PLACEHOLDER);
        }
        return element;
    }

    private static AiAuthInputElement withValue(AiAuthInputElement element, String value) {
        return new AiAuthInputElement(
                element.tag(),
                element.type(),
                element.id(),
                element.name(),
                element.label(),
                element.placeholder(),
                value,
                element.options(),
                element.visible());
    }

    // ─── LLM turn ─────────────────────────────────────────────────────────────

    AiAuthResponse askLlm(AiAuthTurnPayload payload) {
        ChatResponse response;
        try {
            String payloadJson = mapper.writeValueAsString(payload);
            ChatRequest request =
                    ChatRequest.builder()
                            .messages(
                                    SystemMessage.from(SYSTEM_PROMPT),
                                    UserMessage.from(payloadJson))
                            .responseFormat(ResponseFormat.JSON)
                            .build();
            response = llm.chat(request);
        } catch (Exception e) {
            LOGGER.error("LLM call failed: {}", e.getMessage(), e);
            reportLlmError(
                    Constant.messages.getString(
                            "authhelper.auth.method.ai.chat.error.call.failed", e.getMessage()));
            return null;
        }

        if (chatTab != null) {
            chatTab.addTokenUsage(response.tokenUsage());
        }

        try {
            return LlmCommunicationService.mapResponse(response, AiAuthResponse.class);
        } catch (Exception e) {
            String rawResponse = response.aiMessage() != null ? response.aiMessage().text() : null;
            LOGGER.error("Failed to parse LLM response: {}", rawResponse, e);
            reportLlmError(
                    Constant.messages.getString(
                            "authhelper.auth.method.ai.chat.error.unparseable", rawResponse));
            return null;
        }
    }

    private void reportLlmError(String message) {
        if (chatTab != null) {
            chatTab.appendToOutput(LlmChatTabPanel.ERROR_LABEL, message);
        }
    }

    // ─── Action execution ─────────────────────────────────────────────────────

    AiAuthActionResult executeAction(
            WebDriver wd, AiAuthAction action, String username, String password) {
        AiAuthActionType type = action.type();

        if (type == AiAuthActionType.WAIT) {
            try {
                int seconds = Integer.parseInt(action.value());
                if (seconds < 0 || seconds > MAX_WAIT_SECONDS) {
                    return AiAuthActionResult.failed(
                            type,
                            "WAIT value out of range [0, "
                                    + MAX_WAIT_SECONDS
                                    + "]: "
                                    + action.value());
                }
                waitSeconds(seconds);
                return AiAuthActionResult.ok(type, "wait", action.value());
            } catch (Exception e) {
                return AiAuthActionResult.failed(type, "Invalid WAIT value: " + action.value());
            }
        }

        SelectorMatch match = resolveSelector(wd, action.selectors());
        if (match == null) {
            return AiAuthActionResult.failed(
                    type, "No element matched selectors: " + action.selectors());
        }
        WebElement element = match.element();
        String usedSelector = match.selector();

        return switch (type) {
            case CLICK -> {
                try {
                    element.click();
                    yield AiAuthActionResult.ok(type, usedSelector, null);
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            case SEND_KEYS -> {
                try {
                    String value = substituteCredentials(action.value(), username, password);
                    element.clear();
                    element.sendKeys(value);
                    yield AiAuthActionResult.ok(type, usedSelector, action.value());
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            case SELECT -> {
                try {
                    new Select(element).selectByVisibleText(action.value());
                    yield AiAuthActionResult.ok(type, usedSelector, action.value());
                } catch (Exception e) {
                    yield AiAuthActionResult.failed(type, e.getMessage());
                }
            }
            default -> AiAuthActionResult.failed(type, "Unhandled action type: " + type);
        };
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /** A selector that matched an element, paired with the element it matched. */
    private record SelectorMatch(String selector, WebElement element) {}

    private SelectorMatch resolveSelector(WebDriver wd, List<String> selectors) {
        if (selectors == null) return null;
        for (String selector : selectors) {
            try {
                List<WebElement> found = wd.findElements(By.cssSelector(selector));
                if (!found.isEmpty()) {
                    return new SelectorMatch(selector, found.get(0));
                }
            } catch (Exception e) {
                LOGGER.trace("Selector '{}' failed: {}", selector, e.getMessage());
            }
        }
        return null;
    }

    private String substituteCredentials(String value, String username, String password) {
        if (value == null) return null;
        return value.replace(AiAuthTurnPayload.USERNAME_PLACEHOLDER, username)
                .replace(AiAuthTurnPayload.PASSWORD_PLACEHOLDER, password);
    }

    // ─── Chat-tab logging ─────────────────────────────────────────────────────

    private void logTurnContext(
            int step,
            String url,
            String pageTitle,
            List<AiAuthInputElement> elements,
            String visibleText) {
        if (chatTab == null) return;
        long visible = elements.stream().filter(AiAuthInputElement::visible).count();
        StringBuilder msg = new StringBuilder();
        msg.append(Constant.messages.getString("authhelper.auth.method.ai.chat.turn", step, url));
        msg.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.page", pageTitle));
        msg.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.elements",
                                visible,
                                elements.size()));
        if (visibleText != null && !visibleText.isBlank()) {
            msg.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.text", visibleText));
        }
        chatTab.appendToOutput(LlmChatTabPanel.USER_LABEL, msg.toString());
    }

    private void logLlmResponse(AiAuthResponse response) {
        if (chatTab == null) return;
        StringBuilder sb = new StringBuilder();
        sb.append(
                Constant.messages.getString(
                        "authhelper.auth.method.ai.chat.state", response.state()));
        sb.append('\n')
                .append(
                        Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.reasoning", response.reasoning()));
        if (response.actions() != null && !response.actions().isEmpty()) {
            sb.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.actions.header"));
            int n = 1;
            for (AiAuthAction action : response.actions()) {
                sb.append("\n  ")
                        .append(
                                Constant.messages.getString(
                                        "authhelper.auth.method.ai.chat.action.item",
                                        n++,
                                        action.type()));
                if (action.selectors() != null && !action.selectors().isEmpty()) {
                    sb.append(" ").append(action.selectors().get(0));
                }
                if (action.value() != null) {
                    sb.append(" → ").append(action.value());
                }
            }
        }
        if (response.successIndicator() != null) {
            sb.append('\n')
                    .append(
                            Constant.messages.getString(
                                    "authhelper.auth.method.ai.chat.success.indicator",
                                    response.successIndicator().type(),
                                    response.successIndicator().value()));
        }
        chatTab.appendToOutput(LlmChatTabPanel.ASSISTANT_LABEL, sb.toString());
    }

    private void logFinalResult(AiAuthResult result) {
        if (chatTab == null) return;
        String resultWord =
                Constant.messages.getString(
                        result.success()
                                ? "authhelper.auth.method.ai.chat.result.succeeded"
                                : "authhelper.auth.method.ai.chat.result.failed");
        String msg =
                Constant.messages.getString(
                                "authhelper.auth.method.ai.chat.result.header",
                                resultWord,
                                result.finalState())
                        + "\n"
                        + result.reasoning();
        chatTab.appendToOutput(
                result.success() ? LlmChatTabPanel.ASSISTANT_LABEL : LlmChatTabPanel.ERROR_LABEL,
                msg);
    }

    private void waitSeconds(int seconds) {
        waitMillis((long) seconds * 1000);
    }

    private void waitMillis(long ms) {
        if (ms <= 0) return;
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
