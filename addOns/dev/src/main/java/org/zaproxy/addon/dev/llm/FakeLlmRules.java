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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * An ordered list of rules for the fake LLM: the first rule whose pattern is found in the last user
 * message supplies the canned reply.
 */
public class FakeLlmRules {

    /** The reply used when no rule matches. */
    public static final String NO_MATCH_REPLY =
            "The ZAP dev add-on fake LLM has no rule matching this prompt.";

    public record Rule(Pattern pattern, String reply) {}

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.DOTALL;

    private final List<Rule> rules;

    public FakeLlmRules(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    /**
     * Parses rules from JSON of the form {@code [{"match":"regex","reply":"text or JSON object"}]}.
     * A reply which is not a string is used as its JSON text. Invalid entries are skipped.
     *
     * @throws JsonProcessingException if the content is not valid JSON.
     * @throws IllegalArgumentException if the content is not a JSON array.
     */
    public static FakeLlmRules fromJson(String json) throws JsonProcessingException {
        JsonNode array = MAPPER.readTree(json);
        if (array == null || !array.isArray()) {
            throw new IllegalArgumentException("The rules must be a JSON array");
        }
        List<Rule> rules = new ArrayList<>();
        for (JsonNode node : array) {
            JsonNode match = node.get("match");
            JsonNode reply = node.get("reply");
            if (match == null || !match.isTextual() || reply == null) {
                continue;
            }
            try {
                rules.add(
                        new Rule(
                                Pattern.compile(match.asText(), FLAGS),
                                reply.isTextual() ? reply.asText() : reply.toString()));
            } catch (PatternSyntaxException e) {
                // Skip the bad rule, the others are still usable.
            }
        }
        return new FakeLlmRules(rules);
    }

    public Optional<String> match(String prompt) {
        if (prompt == null) {
            return Optional.empty();
        }
        return rules.stream()
                .filter(r -> r.pattern().matcher(prompt).find())
                .map(Rule::reply)
                .findFirst();
    }

    public String replyFor(String prompt) {
        return match(prompt).orElse(NO_MATCH_REPLY);
    }
}
