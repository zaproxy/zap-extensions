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
package org.zaproxy.addon.llmtest.mock;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.TestDirectory;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A mock OpenAI compatible LLM endpoint. Configure the LLM add-on with an "OpenAI compatible"
 * provider with the endpoint {@code http://<host>:<port>/llm/mock/v1} and any model name.
 *
 * <p>Replies come from {@link MockLlmRules}, loaded from the {@code rules.json} file in the {@code
 * llm/mock} directory of the dev add-on's home directory. The file is re-read on every request so
 * it can be edited while ZAP is running.
 *
 * <p>Other add-ons can provide their own rule sets, so that they do not interfere with each other.
 * A rule set called {@code name} is used with the endpoint {@code
 * http://<host>:<port>/llm/mock/<name>/v1}. Its rules are either supplied with {@link
 * #addRuleSet(String, Supplier)} or, by convention, are read from {@code
 * addOnData/dev/llm/mock/<name>/rules.json} which an add-on can include using {@code zapHomeFiles}.
 */
public class MockLlmDir extends TestDirectory {

    private static final Logger LOGGER = LogManager.getLogger(MockLlmDir.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String STATUS_BAD_REQUEST = "400 Bad Request";
    static final String RULES_FILE = "rules.json";
    private static final String COMPLETIONS_PATH = "/v1/chat/completions";
    private static final String MODELS_PATH = "/v1/models";
    private static final String DEFAULT_MODEL = "mock-llm";
    private static final String STATUS_NOT_FOUND = "404 Not Found";

    private static final Pattern RULE_SET_NAME = Pattern.compile("[A-Za-z0-9_-]+");

    private final Map<String, Supplier<String>> ruleSets = new ConcurrentHashMap<>();

    public MockLlmDir(TestProxyServer server, String name) {
        super(server, name);
    }

    /**
     * Adds a rule set, available at {@code /llm/mock/<name>/v1}. The rules are requested for every
     * request so they can change while ZAP is running.
     *
     * @param name the name of the rule set, only letters, digits, {@code _} and {@code -}.
     * @param rules supplies the rules as JSON, see {@link MockLlmRules#fromJson(String)}, or {@code
     *     null} if there are none.
     * @throws IllegalArgumentException if the name is not valid.
     */
    public void addRuleSet(String name, Supplier<String> rules) {
        if (!RULE_SET_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("Invalid rule set name: " + name);
        }
        ruleSets.put(name, rules);
    }

    public void removeRuleSet(String name) {
        ruleSets.remove(name);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        String path = msg.getRequestHeader().getURI().getEscapedPath();
        if (path.endsWith(COMPLETIONS_PATH) && "POST".equals(msg.getRequestHeader().getMethod())) {
            handleApi(msg, getRuleSetName(path, COMPLETIONS_PATH), this::handleCompletion);
        } else if (path.endsWith(MODELS_PATH)) {
            handleApi(msg, getRuleSetName(path, MODELS_PATH), (m, ruleSet) -> handleModels(m));
        } else {
            super.handleMessage(ctx, msg);
        }
    }

    /**
     * Gets the name of the rule set from the path, the segment before the API path, for example
     * {@code /llm/mock/name/v1/models}, which is {@code null} for the default rule set. The default
     * is identified by the full path of this directory, as a rule set can have the same name.
     */
    private String getRuleSetName(String path, String apiPath) {
        String base = path.substring(0, path.length() - apiPath.length());
        return base.equals(getHierarchicName()) ? null : base.substring(base.lastIndexOf('/') + 1);
    }

    private void handleApi(
            HttpMessage msg, String ruleSet, BiConsumer<HttpMessage, String> handler) {
        if (ruleSet != null && !isKnownRuleSet(ruleSet)) {
            ObjectNode error = MAPPER.createObjectNode();
            error.putObject("error")
                    .put("message", "No such rule set: " + ruleSet)
                    .put("type", "invalid_request_error");
            setResponse(msg, STATUS_NOT_FOUND, error);
            return;
        }
        handler.accept(msg, ruleSet);
    }

    private boolean isKnownRuleSet(String ruleSet) {
        return ruleSets.containsKey(ruleSet) || readRuleSetFile(ruleSet) != null;
    }

    private String readRuleSetFile(String ruleSet) {
        return RULE_SET_NAME.matcher(ruleSet).matches()
                ? getServer().getTextFile(this, ruleSet + "/" + RULES_FILE)
                : null;
    }

    private void handleCompletion(HttpMessage msg, String ruleSet) {
        JsonNode request;
        try {
            request = MAPPER.readTree(msg.getRequestBody().toString());
        } catch (JsonProcessingException e) {
            request = null;
            LOGGER.warn("Mock LLM received an unparseable request: {}", e.getMessage());
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
        String reply = getRules(ruleSet).replyFor(prompt);
        LOGGER.debug("Mock LLM prompt: {} reply: {}", prompt, reply);
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

    private MockLlmRules getRules(String ruleSet) {
        String json;
        if (ruleSet == null) {
            json = getServer().getTextFile(this, RULES_FILE);
        } else {
            Supplier<String> rules = ruleSets.get(ruleSet);
            json = rules != null ? rules.get() : readRuleSetFile(ruleSet);
        }
        if (json == null) {
            LOGGER.warn("No rules found for {}, the mock LLM has no rules.", ruleSet);
        } else {
            try {
                return MockLlmRules.fromJson(json);
            } catch (JsonProcessingException | IllegalArgumentException e) {
                LOGGER.warn(
                        "Invalid {}, the mock LLM has no rules: {}", RULES_FILE, e.getMessage());
            }
        }
        return new MockLlmRules(List.of());
    }

    /** Returns the text of the last message with the role "user", or an empty string. */
    static String getLastUserMessage(JsonNode request) {
        JsonNode messages = request.path("messages");
        if (!messages.isArray()) {
            return "";
        }
        for (int i = messages.size() - 1; i >= 0; i--) {
            JsonNode message = messages.get(i);
            if (message.isObject() && "user".equals(message.path("role").asText())) {
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
                .put("id", "chatcmpl-mock")
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
