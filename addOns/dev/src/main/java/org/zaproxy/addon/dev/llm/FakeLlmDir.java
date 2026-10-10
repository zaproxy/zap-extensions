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
package org.zaproxy.addon.dev.llm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A fake OpenAI compatible LLM endpoint. Configure the LLM add-on with an "OpenAI compatible"
 * provider with the endpoint {@code http://<host>:<port>/llm/fake/v1} and any model name.
 *
 * <p>Replies come from {@link FakeLlmRules}, loaded from the {@code rules.json} file in the {@code
 * llm/fake} directory of the dev add-on's home directory. The file is re-read on every request so
 * it can be edited while ZAP is running.
 */
public class FakeLlmDir extends TestDirectory {

    private static final Logger LOGGER = LogManager.getLogger(FakeLlmDir.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String STATUS_BAD_REQUEST = "400 Bad Request";
    static final String RULES_FILE = "rules.json";
    private static final String COMPLETIONS_PATH = "/v1/chat/completions";
    private static final String MODELS_PATH = "/v1/models";
    private static final String DEFAULT_MODEL = "fake-llm";

    public FakeLlmDir(TestProxyServer server, String name) {
        super(server, name);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String path = msg.getRequestHeader().getURI().getEscapedPath();
        if (path.endsWith(COMPLETIONS_PATH) && "POST".equals(msg.getRequestHeader().getMethod())) {
            handleCompletion(msg);
        } else if (path.endsWith(MODELS_PATH)) {
            handleModels(msg);
        } else {
            super.handleMessage(ctx, msg);
        }
    }

    private void handleCompletion(HttpMessage msg) {
        JsonNode request;
        try {
            request = MAPPER.readTree(msg.getRequestBody().toString());
        } catch (JsonProcessingException e) {
            request = null;
            LOGGER.warn("Fake LLM received an unparseable request: {}", e.getMessage());
        }
        if (request == null || !request.isObject()) {
            ObjectNode error = MAPPER.createObjectNode();
            error.putObject("error")
                    .put("message", "Invalid JSON")
                    .put("type", "invalid_request_error");
            setResponse(msg, STATUS_BAD_REQUEST, error);
            return;
        }
        String model = request.path("model").asText(DEFAULT_MODEL);
        String prompt = getLastUserMessage(request);
        String reply = getRules().replyFor(prompt);
        LOGGER.debug("Fake LLM prompt: {} reply: {}", prompt, reply);
        setResponse(msg, TestProxyServer.STATUS_OK, buildCompletion(model, prompt, reply));
    }

    private void handleModels(HttpMessage msg) {
        ObjectNode models = MAPPER.createObjectNode();
        models.put("object", "list");
        models.putArray("data")
                .addObject()
                .put("id", DEFAULT_MODEL)
                .put("object", "model")
                .put("owned_by", "zap-dev-addon");
        setResponse(msg, TestProxyServer.STATUS_OK, models);
    }

    private FakeLlmRules getRules() {
        String json = getServer().getTextFile(this, RULES_FILE);
        if (json == null) {
            LOGGER.warn("No {} found, the fake LLM has no rules.", RULES_FILE);
        } else {
            try {
                return FakeLlmRules.fromJson(json);
            } catch (JsonProcessingException | IllegalArgumentException e) {
                LOGGER.warn(
                        "Invalid {}, the fake LLM has no rules: {}", RULES_FILE, e.getMessage());
            }
        }
        return new FakeLlmRules(List.of());
    }

    /** Returns the text of the last message with the role "user", or an empty string. */
    static String getLastUserMessage(JsonNode request) {
        JsonNode messages = request.path("messages");
        for (int i = messages.size() - 1; i >= 0; i--) {
            JsonNode message = messages.get(i);
            if ("user".equals(message.path("role").asText())) {
                return getContentText(message.path("content"));
            }
        }
        return "";
    }

    /** The content is either a string or an array of parts, only the text parts are used. */
    private static String getContentText(JsonNode content) {
        if (content.isArray()) {
            StringBuilder sb = new StringBuilder();
            content.forEach(part -> sb.append(part.path("text").asText("")));
            return sb.toString();
        }
        return content.asText("");
    }

    static ObjectNode buildCompletion(String model, String prompt, String reply) {
        // Rough token counts, just so that the usage is not empty.
        int promptTokens = Math.max(1, prompt.length() / 4);
        int completionTokens = Math.max(1, reply.length() / 4);

        ObjectNode completion = MAPPER.createObjectNode();
        completion
                .put("id", "chatcmpl-fake")
                .put("object", "chat.completion")
                .put("created", System.currentTimeMillis() / 1000)
                .put("model", model);
        ObjectNode choice = completion.putArray("choices").addObject();
        choice.put("index", 0).put("finish_reason", "stop");
        choice.putObject("message").put("role", "assistant").put("content", reply);
        completion
                .putObject("usage")
                .put("prompt_tokens", promptTokens)
                .put("completion_tokens", completionTokens)
                .put("total_tokens", promptTokens + completionTokens);
        return completion;
    }

    private static void setResponse(HttpMessage msg, String status, JsonNode body) {
        try {
            msg.setResponseBody(body.toString());
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            status, "application/json", msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
