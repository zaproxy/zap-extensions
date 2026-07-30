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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ResponseFormat;
import dev.langchain4j.model.chat.request.ResponseFormatType;
import dev.langchain4j.model.chat.request.json.JsonObjectSchema;
import dev.langchain4j.model.chat.request.json.JsonSchema;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.HashMap;
import java.util.Map;
import javax.swing.SwingUtilities;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.Stats;

public class LlmActionReviewAlert {

    public static final String AI_REVIEWED_TAG_KEY = "AI-Reviewed";

    /** Characters of response body to include on each side of the evidence. */
    static final int EVIDENCE_CONTEXT_CHARS = 500;

    private static final Logger LOGGER = LogManager.getLogger(LlmActionReviewAlert.class);

    record AlertFeedback(int level, String explanation) {}

    private ExtensionAlert extAlert;
    private ExtensionLlm extLlm;

    private static final String ALERT_REVIEW_PROMPT =
            """
            Your task is to review the following finding from ZAP (Zed Attack Proxy).
            The confidence level allows you to specify how confident you are in the validity of the finding:
            - 0 if it's False Positive
            - 1 if it's Low
            - 2 if it's Medium
            - 3 if it's High

            Output format:
            {
              "level": integer,
              "explanation": string
            }

            The alert title is: {{title}}

            The alert is described as follows: {{description}}

            {{evidenceSection}}
            """;

    private static final String ALERT_REVIEW_EVIDENCE =
            """
            As evidence, the HTTP message contains:
            ---
            {{evidence}}
            ---
            """;

    private static final String ALERT_REVIEW_NO_EVIDENCE =
            """
            There was no evidence associated with this alert. This often indicates that expected content was missing from the HTTP message.
            """;

    private static final String ALERT_REVIEW_OTHER_INFO =
            """
            As alert other info contains:
            ---
            {{other}}
            ---
            """;

    private static final String ALERT_REVIEW_REQUEST =
            """
            The HTTP request is:
            ---
            {{request}}
            ---
            """;

    private static final String ALERT_REVIEW_RESPONSE_HEADERS =
            """
            The HTTP response headers are:
            ---
            {{responseHeaders}}
            ---
            """;

    private static final String ALERT_REVIEW_EVIDENCE_CONTEXT =
            """
            Context around the evidence in the response:
            ---
            {{evidenceContext}}
            ---
            """;

    private static final String ALERT_REVIEW_GOAL =
            "Provide a short consistent explanation of the new score.\n";

    public LlmActionReviewAlert(ExtensionLlm extLlm, ExtensionAlert extAlert) {
        this.extLlm = extLlm;
        this.extAlert = extAlert;
    }

    public void reviewAlert(Alert alert)
            throws JsonMappingException,
                    JsonProcessingException,
                    HttpMalformedHeaderException,
                    DatabaseException {
        reviewAlert(alert, false);
    }

    public void reviewAlert(Alert alert, boolean force)
            throws JsonMappingException,
                    JsonProcessingException,
                    HttpMalformedHeaderException,
                    DatabaseException {

        if (!force && isPreviouslyReviewed(alert)) {
            LOGGER.debug("Skipping previously reviewed alert : {} ", alert.getName());
            return;
        }

        ResponseFormat responseFormat =
                ResponseFormat.builder()
                        .type(ResponseFormatType.JSON)
                        .jsonSchema(
                                JsonSchema.builder()
                                        .name("AlertFeedback")
                                        .rootElement(
                                                JsonObjectSchema.builder()
                                                        .addIntegerProperty(
                                                                "level",
                                                                "The confidence level, where 0 is false positive, 1 is low, 2 is mediam, and 3 is high")
                                                        .addStringProperty(
                                                                "explanation",
                                                                "A textual explanation for the assigned confidence level")
                                                        .required("level", "explanation")
                                                        .build())
                                        .build())
                        .build();

        String promptText = buildPrompt(alert, isDefaultProviderTrusted());

        UserMessage userMessage = UserMessage.from(promptText);

        ChatRequest chatRequest =
                ChatRequest.builder().responseFormat(responseFormat).messages(userMessage).build();

        String outputTabName =
                Constant.messages.getString("alertFilters.llm.reviewalert.output.tab");
        LlmChatTabPanel chatTab = extLlm.getOrCreateChatTab("ALERT_REVIEW", outputTabName);
        if (chatTab != null) {
            chatTab.appendToOutput(LlmChatTabPanel.USER_LABEL, promptText);
            SwingUtilities.invokeLater(
                    () -> {
                        chatTab.showTab();
                        chatTab.setProcessing(true);
                    });
        }

        LlmCommunicationService commsService = extLlm.getCommunicationService("ALERT_REVIEW", null);
        boolean success = false;
        try {
            ChatResponse resp = commsService.chat(chatRequest);
            if (chatTab != null) {
                // Alert review manages the chat UI itself (so uses a log listener), but still
                // needs to accumulate token usage on the tab toolbar.
                chatTab.addTokenUsage(resp.tokenUsage());
            }
            AlertFeedback feedback = LlmCommunicationService.mapResponse(resp, AlertFeedback.class);

            if (chatTab != null) {
                chatTab.appendToOutput(
                        LlmChatTabPanel.ASSISTANT_LABEL,
                        confidenceLevelName(feedback.level()) + "\n" + feedback.explanation());
            }

            if (feedback.level() == alert.getConfidence()) {
                Stats.incCounter("stats.llm.alertreview.result.same");
            } else {
                Stats.incCounter("stats.llm.alertreview.result.changed");
            }

            LOGGER.debug(
                    "Confidence level from LLM : {} | Explanation : {}",
                    feedback.level(),
                    feedback.explanation());
            alert.setConfidence(feedback.level());
            alert.setOtherInfo(getUpdatedOtherInfo(alert, feedback.explanation()));
            Map<String, String> alertTags = new HashMap<>(alert.getTags());

            alertTags.putIfAbsent(AI_REVIEWED_TAG_KEY, "");
            alert.setTags(alertTags);

            extAlert.updateAlert(alert);
            extAlert.updateAlertInTree(alert);
            if (alert.getHistoryRef() != null) {
                alert.getHistoryRef().updateAlert(alert);
                if (alert.getHistoryRef().getSiteNode() != null) {
                    // Needed if the same alert was raised on another href for the same SiteNode
                    alert.getHistoryRef().getSiteNode().updateAlert(alert);
                }
            }
            success = true;
        } finally {
            if (!success && chatTab != null) {
                SwingUtilities.invokeLater(() -> chatTab.setProcessing(false));
            }
        }
    }

    private boolean isDefaultProviderTrusted() {
        LlmProviderConfig config = extLlm.getDefaultProviderConfig();
        return config != null && config.isTrusted();
    }

    /**
     * Builds the alert review prompt. When {@code trusted} is {@code true} and the alert has an
     * associated HTTP message, also includes the full request, response headers, and (when the
     * evidence appears in the response body) surrounding context.
     */
    static String buildPrompt(Alert alert, boolean trusted) {
        String evidenceSection =
                StringUtils.isBlank(alert.getEvidence())
                        ? ALERT_REVIEW_NO_EVIDENCE
                        : ALERT_REVIEW_EVIDENCE.replace("{{evidence}}", alert.getEvidence());
        StringBuilder prompt =
                new StringBuilder(
                        ALERT_REVIEW_PROMPT
                                .replace("{{title}}", alert.getName())
                                .replace("{{description}}", alert.getDescription())
                                .replace("{{evidenceSection}}", evidenceSection));

        if (StringUtils.isNotBlank(alert.getOtherInfo())) {
            prompt.append(ALERT_REVIEW_OTHER_INFO.replace("{{other}}", alert.getOtherInfo()));
        }

        if (trusted) {
            appendTrustedMessageDetails(prompt, alert);
        }

        prompt.append(ALERT_REVIEW_GOAL);
        return prompt.toString();
    }

    private static void appendTrustedMessageDetails(StringBuilder prompt, Alert alert) {
        HttpMessage msg = alert.getMessage();
        if (msg == null) {
            return;
        }

        StringBuilder request = new StringBuilder(msg.getRequestHeader().toString());
        if (msg.getRequestBody().length() > 0) {
            request.append(msg.getRequestBody());
        }
        prompt.append(ALERT_REVIEW_REQUEST.replace("{{request}}", request.toString()));

        if (!msg.getResponseHeader().isEmpty()) {
            prompt.append(
                    ALERT_REVIEW_RESPONSE_HEADERS.replace(
                            "{{responseHeaders}}", msg.getResponseHeader().toString()));
        }

        String evidenceContext =
                extractEvidenceContext(
                        msg.getResponseBody().toString(),
                        alert.getEvidence(),
                        EVIDENCE_CONTEXT_CHARS);
        if (evidenceContext != null) {
            prompt.append(
                    ALERT_REVIEW_EVIDENCE_CONTEXT.replace("{{evidenceContext}}", evidenceContext));
        }
    }

    /**
     * Returns a slice of {@code text} around the first occurrence of {@code evidence}, or {@code
     * null} if the evidence is blank or not present.
     */
    static String extractEvidenceContext(String text, String evidence, int contextChars) {
        if (StringUtils.isBlank(text) || StringUtils.isBlank(evidence)) {
            return null;
        }
        int idx = text.indexOf(evidence);
        if (idx < 0) {
            return null;
        }
        int offset = Math.max(0, idx - contextChars);
        int maxWidth = evidence.length() + 2 * contextChars;
        return StringUtils.abbreviate(text, offset, Math.max(maxWidth, 4));
    }

    protected static boolean isPreviouslyReviewed(Alert alert) {
        return alert.getTags().containsKey(AI_REVIEWED_TAG_KEY);
    }

    private static String getUpdatedOtherInfo(Alert alert, String explanation) {
        return Constant.messages.getString(
                "alertFilters.llm.reviewalert.otherinfo", alert.getOtherInfo(), explanation);
    }

    private static String confidenceLevelName(int level) {
        return switch (level) {
            case Alert.CONFIDENCE_FALSE_POSITIVE ->
                    Constant.messages.getString(
                            "alertFilters.llm.reviewalert.confidence.falsepositive");
            case Alert.CONFIDENCE_LOW ->
                    Constant.messages.getString("alertFilters.llm.reviewalert.confidence.low");
            case Alert.CONFIDENCE_MEDIUM ->
                    Constant.messages.getString("alertFilters.llm.reviewalert.confidence.medium");
            case Alert.CONFIDENCE_HIGH ->
                    Constant.messages.getString("alertFilters.llm.reviewalert.confidence.high");
            default ->
                    Constant.messages.getString(
                            "alertFilters.llm.reviewalert.confidence.unknown", level);
        };
    }
}
