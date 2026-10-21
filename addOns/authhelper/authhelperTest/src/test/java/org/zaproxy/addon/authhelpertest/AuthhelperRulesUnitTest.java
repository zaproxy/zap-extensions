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
package org.zaproxy.addon.authhelpertest;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.zaproxy.addon.llmtest.mock.MockLlmRules;

/** Unit tests for the {@code authhelper} rule set, which drives the multi step auth test app. */
class AuthhelperRulesUnitTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String RULES_DIR = "src/main/zapHomeFiles/addOnData/dev/server/llm/mock/";
    private static final String INDEX_URL = "http://localhost:9091/auth/multi-step-auth/";

    private static String payload(int step, String url) {
        return "{\"step\":" + step + ",\"url\":\"" + url + "\",\"pageTitle\":\"ZAP Test Server\"}";
    }

    private static JsonNode replyFor(String ruleSet, int step, String url) throws Exception {
        MockLlmRules rules =
                MockLlmRules.fromJson(Files.readString(Path.of(RULES_DIR, ruleSet, "rules.json")));
        return MAPPER.readTree(rules.replyFor(payload(step, url)));
    }

    private static JsonNode replyFor(String url) throws Exception {
        return replyFor("authhelper", 1, url);
    }

    @ParameterizedTest
    @CsvSource({
        "http://localhost:9091/auth/multi-step-auth/, SEND_KEYS",
        "http://localhost:9091/auth/multi-step-auth/index.html, SEND_KEYS",
        "http://localhost:9091/auth/multi-step-auth/step2, SELECT",
        "http://localhost:9091/auth/multi-step-auth/password, SEND_KEYS"
    })
    void shouldContinueFlowForEachStep(String url, String firstAction) throws Exception {
        JsonNode reply = replyFor(url);
        assertThat(reply.get("state").asText(), is("IN_PROGRESS"));
        assertThat(reply.get("actions").get(0).get("type").asText(), is(firstAction));
    }

    @Test
    void shouldSelectRequiredDomainOnFirstStep() throws Exception {
        assertThat(
                replyFor("http://localhost:9091/auth/multi-step-auth/").toString(),
                containsString("\"value\":\"Project1\""));
    }

    @Test
    void shouldReportSuccessOnHomePage() throws Exception {
        JsonNode reply = replyFor("http://localhost:9091/auth/multi-step-auth/home");
        assertThat(reply.get("state").asText(), is("SUCCESS"));
        assertThat(reply.get("actions").size(), is(0));
    }

    @Test
    void shouldSelectWrongDomainOnFirstStepInWrongDomainRuleSet() throws Exception {
        assertThat(
                replyFor("authhelper-wrong-domain", 1, INDEX_URL).toString(),
                containsString("\"value\":\"Project2\""));
    }

    @ParameterizedTest
    @CsvSource({"2, step2, SELECT", "3, password, SEND_KEYS"})
    void shouldContinueIntermediateStepsInWrongDomainRuleSet(int step, String page, String action)
            throws Exception {
        JsonNode reply = replyFor("authhelper-wrong-domain", step, INDEX_URL + page);
        assertThat(reply.get("state").asText(), is("IN_PROGRESS"));
        assertThat(reply.get("actions").get(0).get("type").asText(), is(action));
    }

    @Test
    void shouldFailWhenLoginFormIsShownAgainInWrongDomainRuleSet() throws Exception {
        JsonNode reply = replyFor("authhelper-wrong-domain", 4, INDEX_URL);
        assertThat(reply.get("state").asText(), is("FAILURE"));
        assertThat(reply.get("actions").size(), is(0));
    }

    @Test
    void shouldNotFailOnFirstStepWhenLoginFormIsShown() throws Exception {
        assertThat(
                replyFor("authhelper-wrong-domain", 1, INDEX_URL).get("state").asText(),
                is("IN_PROGRESS"));
    }
}
