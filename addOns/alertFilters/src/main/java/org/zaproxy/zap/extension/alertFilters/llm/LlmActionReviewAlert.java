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
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.Stats;

public class LlmActionReviewAlert {

    public static final String AI_REVIEWED_TAG_KEY = "AI-Reviewed";

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

            As evidence, the HTTP message contains:
            ---
            {{evidence}}
            ---
            """;

    private static final String ALERT_REVIEW_OTHER_INFO =
            """
            As alert other info contains:
            ---
            {{other}}
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

        if (isPreviouslyReviewed(alert)) {
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

        UserMessage userMessage =
                UserMessage.from(
                        ALERT_REVIEW_PROMPT
                                        .replace("{{title}}", alert.getName())
                                        .replace("{{description}}", alert.getDescription())
                                        .replace("{{evidence}}", alert.getEvidence())
                                + (StringUtils.isNotBlank(alert.getOtherInfo())
                                        ? ALERT_REVIEW_OTHER_INFO.replace(
                                                "{{other}}", alert.getOtherInfo())
                                        : "")
                                + ALERT_REVIEW_GOAL);

        ChatRequest chatRequest =
                ChatRequest.builder().responseFormat(responseFormat).messages(userMessage).build();

        LlmCommunicationService commsService =
                extLlm.getCommunicationService(
                        "ALERT_REVIEW",
                        Constant.messages.getString("alertFilters.llm.reviewalert.output.tab"));

        ChatResponse resp = commsService.chat(chatRequest);
        commsService.switchToOutputTab();
        AlertFeedback feedback = LlmCommunicationService.mapResponse(resp, AlertFeedback.class);

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
    }

    protected static boolean isPreviouslyReviewed(Alert alert) {
        return alert.getTags().containsKey(AI_REVIEWED_TAG_KEY);
    }

    private static String getUpdatedOtherInfo(Alert alert, String explanation) {
        return Constant.messages.getString(
                "alertFilters.llm.reviewalert.otherinfo", alert.getOtherInfo(), explanation);
    }
}
