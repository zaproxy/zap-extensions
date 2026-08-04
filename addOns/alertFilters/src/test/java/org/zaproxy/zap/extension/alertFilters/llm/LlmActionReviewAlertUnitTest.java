/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.output.TokenUsage;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link LlmActionReviewAlert}. */
class LlmActionReviewAlertUnitTest extends TestUtils {

    static ExtensionLlm extLlm;
    static LlmActionReviewAlert action;

    @BeforeAll
    static void beforeAll() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extLlm = mock(ExtensionLlm.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionLlm.class)).willReturn(extLlm);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        action =
                new LlmActionReviewAlert(
                        extLlm,
                        mock(ExtensionAlert.class, withSettings().strictness(Strictness.LENIENT)));
    }

    @BeforeEach
    void beforeEach() {
        given(extLlm.getDefaultProviderConfig()).willReturn(null);
    }

    @Test
    void shouldNotBeConsideredReviewdIfNoTags() {
        // Given
        Alert alert = new Alert(-1);
        // When
        boolean result = LlmActionReviewAlert.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldNotBeConsideredReviewdIfNotMarkedAsSuch() {
        // Given
        Alert alert = new Alert(-1);
        alert.setTags(Map.of("test", "test"));
        // When
        boolean result = LlmActionReviewAlert.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldIncludeAlertTitleAndDescriptionInPrompt() throws Exception {
        // Given
        LlmCommunicationService comms = mockCommsReturning("{}");
        ArgumentCaptor<ChatRequest> argument = ArgumentCaptor.forClass(ChatRequest.class);

        Alert alert = new Alert(-1);
        alert.setName("Test Name");
        alert.setDescription("Test Description");

        // When
        action.reviewAlert(alert);

        // Then
        verify(comms).chat(argument.capture());
        String prompt = argument.getValue().messages().get(0).toString();
        assertThat(prompt, containsString("Test Name"));
        assertThat(prompt, containsString("Test Description"));
    }

    @Test
    void shouldIncludeAlertOtherInfoInPrompt() throws Exception {
        // Given
        LlmCommunicationService comms = mockCommsReturning("{}");
        ArgumentCaptor<ChatRequest> argument = ArgumentCaptor.forClass(ChatRequest.class);

        Alert alert = new Alert(-1);
        alert.setOtherInfo("Test Other Info");

        // When
        action.reviewAlert(alert);

        // Then
        verify(comms).chat(argument.capture());
        assertThat(
                argument.getValue().messages().get(0).toString(),
                containsString("Test Other Info"));
    }

    @Test
    void shouldStateWhenAlertHasNoEvidence() {
        // Given
        Alert alert = new Alert(-1);
        alert.setName("Missing Header");
        alert.setDescription("Expected header was not present");
        alert.setEvidence("");

        // When
        String prompt = LlmActionReviewAlert.buildPrompt(alert, false);

        // Then
        assertThat(
                prompt,
                containsString(
                        "There was no evidence associated with this alert. This often indicates that expected content was missing from the HTTP message."));
        assertThat(prompt, not(containsString("As evidence, the HTTP message contains:")));
    }

    @Test
    void shouldNotIncludeHttpMessageDetailsWhenProviderUntrusted() throws Exception {
        // Given
        Alert alert = alertWithMessage("secret-evidence");

        // When
        String prompt = LlmActionReviewAlert.buildPrompt(alert, false);

        // Then
        assertThat(prompt, containsString("secret-evidence"));
        assertThat(prompt, not(containsString("The HTTP request is:")));
        assertThat(prompt, not(containsString("The HTTP response headers are:")));
        assertThat(prompt, not(containsString("Context around the evidence")));
        assertThat(prompt, not(containsString("GET http://example.com/test HTTP/1.1")));
    }

    @Test
    void shouldIncludeRequestResponseHeadersAndEvidenceContextWhenTrusted() throws Exception {
        // Given
        Alert alert = alertWithMessage("secret-evidence");
        given(extLlm.getDefaultProviderConfig())
                .willReturn(
                        new LlmProviderConfig(
                                "ollama",
                                LlmProvider.OLLAMA,
                                "",
                                "http://localhost",
                                List.of("model"),
                                true));
        LlmCommunicationService comms = mockCommsReturning("{}");
        ArgumentCaptor<ChatRequest> argument = ArgumentCaptor.forClass(ChatRequest.class);

        // When
        action.reviewAlert(alert);

        // Then
        verify(comms).chat(argument.capture());
        String prompt = argument.getValue().messages().get(0).toString();
        assertThat(prompt, containsString("The HTTP request is:"));
        assertThat(prompt, containsString("GET http://example.com/test HTTP/1.1"));
        assertThat(prompt, containsString("request-body"));
        assertThat(prompt, containsString("The HTTP response headers are:"));
        assertThat(prompt, containsString("HTTP/1.1 200 OK"));
        assertThat(prompt, containsString("X-Test: value"));
        assertThat(prompt, containsString("Context around the evidence in the response:"));
        assertThat(prompt, containsString("before secret-evidence after"));
    }

    @Test
    void shouldOmitEvidenceContextWhenEvidenceNotInResponseBody() throws Exception {
        // Given
        Alert alert = alertWithMessage("not-in-body");
        alert.setEvidence("missing-evidence");

        // When
        String prompt = LlmActionReviewAlert.buildPrompt(alert, true);

        // Then
        assertThat(prompt, containsString("The HTTP request is:"));
        assertThat(prompt, containsString("The HTTP response headers are:"));
        assertThat(prompt, not(containsString("Context around the evidence")));
    }

    @Test
    void shouldExtractEvidenceContextWithEllipsisWhenTruncated() {
        // Given
        String prefix = "a".repeat(2000);
        String suffix = "b".repeat(2000);
        String text = prefix + "EVIDENCE" + suffix;

        // When
        String context =
                LlmActionReviewAlert.extractEvidenceContext(
                        text, "EVIDENCE", LlmActionReviewAlert.EVIDENCE_CONTEXT_CHARS);

        // Then
        assertThat(context, is(not(nullValue())));
        assertThat(context, containsString("EVIDENCE"));
        assertThat(context.startsWith("..."), is(true));
        assertThat(context.endsWith("..."), is(true));
        assertThat(
                context.length(),
                is(equalTo("EVIDENCE".length() + 2 * LlmActionReviewAlert.EVIDENCE_CONTEXT_CHARS)));
    }

    @Test
    void shouldReturnNullEvidenceContextWhenNotFound() {
        assertThat(LlmActionReviewAlert.extractEvidenceContext("abc", "xyz", 10), is(nullValue()));
        assertThat(LlmActionReviewAlert.extractEvidenceContext("abc", "", 10), is(nullValue()));
        assertThat(LlmActionReviewAlert.extractEvidenceContext("", "x", 10), is(nullValue()));
    }

    @Test
    void shouldUpdateChatTabTokenUsageFromResponse() throws Exception {
        // Given
        TokenUsage usage = new TokenUsage(10, 5, 15);
        LlmChatTabPanel chatTab =
                mock(LlmChatTabPanel.class, withSettings().strictness(Strictness.LENIENT));
        given(extLlm.getOrCreateChatTab(eq("ALERT_REVIEW"), anyString())).willReturn(chatTab);
        mockCommsReturning("{\"level\":2,\"explanation\":\"ok\"}", usage);

        // When
        action.reviewAlert(new Alert(-1));

        // Then
        verify(chatTab).addTokenUsage(usage);
    }

    private static LlmCommunicationService mockCommsReturning(String json) throws Exception {
        return mockCommsReturning(json, null);
    }

    private static LlmCommunicationService mockCommsReturning(String json, TokenUsage usage)
            throws Exception {
        LlmCommunicationService comms = mock(LlmCommunicationService.class);
        given(extLlm.getCommunicationService(anyString(), any())).willReturn(comms);
        ChatResponse resp = mock(ChatResponse.class);
        given(comms.chat(any(ChatRequest.class))).willReturn(resp);
        AiMessage aiMsg = mock(AiMessage.class);
        given(resp.aiMessage()).willReturn(aiMsg);
        given(aiMsg.text()).willReturn(json);
        if (usage != null) {
            given(resp.tokenUsage()).willReturn(usage);
        }
        return comms;
    }

    private static Alert alertWithMessage(String evidence) throws Exception {
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET /test HTTP/1.1\r\nHost: example.com\r\n");
        msg.setRequestBody("request-body");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: value\r\n");
        msg.setResponseBody("before " + evidence + " after");
        Alert alert = new Alert(-1);
        alert.setName("Alert");
        alert.setDescription("Description");
        alert.setEvidence(evidence);
        alert.setMessage(msg);
        return alert;
    }
}
