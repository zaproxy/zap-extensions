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
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AiAuthSchemaUnitTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
    }

    @Nested
    class AiAuthResponseDeserialization {

        @Test
        void shouldDeserializeInProgressResponse() throws Exception {
            String json =
                    """
                    {
                      "state": "IN_PROGRESS",
                      "reasoning": "Filling username and selecting domain.",
                      "actions": [
                        { "type": "SEND_KEYS", "selectors": ["#user", "[name='user']"], "value": "{{username}}" },
                        { "type": "SELECT",    "selectors": ["#domain"],                "value": "Project1" },
                        { "type": "CLICK",     "selectors": ["#next"],                  "value": null }
                      ],
                      "successIndicator": null
                    }
                    """;

            AiAuthResponse response = mapper.readValue(json, AiAuthResponse.class);

            assertThat(response.state(), is(AiAuthState.IN_PROGRESS));
            assertThat(response.reasoning(), equalTo("Filling username and selecting domain."));
            assertThat(response.actions(), hasSize(3));
            assertThat(response.actions().get(0).type(), is(AiAuthActionType.SEND_KEYS));
            assertThat(response.actions().get(0).selectors(), contains("#user", "[name='user']"));
            assertThat(response.actions().get(0).value(), equalTo("{{username}}"));
            assertThat(response.actions().get(1).type(), is(AiAuthActionType.SELECT));
            assertThat(response.actions().get(1).value(), equalTo("Project1"));
            assertThat(response.actions().get(2).type(), is(AiAuthActionType.CLICK));
            assertThat(response.actions().get(2).value(), nullValue());
            assertThat(response.successIndicator(), nullValue());
            assertThat(response.isTerminal(), is(false));
        }

        @Test
        void shouldDeserializeSuccessResponse() throws Exception {
            String json =
                    """
                    {
                      "state": "SUCCESS",
                      "reasoning": "URL changed to home.html.",
                      "actions": [],
                      "successIndicator": { "type": "URL_PATTERN", "value": "home.html" }
                    }
                    """;

            AiAuthResponse response = mapper.readValue(json, AiAuthResponse.class);

            assertThat(response.state(), is(AiAuthState.SUCCESS));
            assertThat(response.actions(), empty());
            assertThat(response.successIndicator(), notNullValue());
            assertThat(
                    response.successIndicator().type(), is(AiAuthSuccessIndicatorType.URL_PATTERN));
            assertThat(response.successIndicator().value(), equalTo("home.html"));
            assertThat(response.isTerminal(), is(true));
        }

        @ParameterizedTest
        @ValueSource(strings = {"FAILURE", "MFA_REQUIRED", "CAPTCHA_DETECTED"})
        void shouldDeserializeOtherTerminalResponses(String state) throws Exception {
            String json =
                    """
                    {
                      "state": "%s",
                      "reasoning": "Some reason.",
                      "actions": [],
                      "successIndicator": null
                    }
                    """
                            .formatted(state);

            AiAuthResponse response = mapper.readValue(json, AiAuthResponse.class);

            assertThat(response.state(), is(AiAuthState.valueOf(state)));
            assertThat(response.isTerminal(), is(true));
        }

        @Test
        void shouldIgnoreUnknownFieldsInResponse() throws Exception {
            String json =
                    """
                    {
                      "state": "IN_PROGRESS",
                      "reasoning": "Working.",
                      "actions": [],
                      "successIndicator": null,
                      "confidence": 0.95,
                      "futureField": "ignored"
                    }
                    """;

            AiAuthResponse response = mapper.readValue(json, AiAuthResponse.class);

            assertThat(response.state(), is(AiAuthState.IN_PROGRESS));
        }

        @Test
        void shouldIgnoreUnknownFieldsInAction() throws Exception {
            String json =
                    """
                    {
                      "state": "IN_PROGRESS",
                      "reasoning": "Working.",
                      "actions": [
                        {
                          "type": "CLICK",
                          "selectors": ["#btn"],
                          "value": null,
                          "description": "Click the submit button",
                          "waitAfterMs": 500
                        }
                      ],
                      "successIndicator": null
                    }
                    """;

            AiAuthResponse response = mapper.readValue(json, AiAuthResponse.class);

            assertThat(response.actions(), hasSize(1));
            assertThat(response.actions().get(0).type(), is(AiAuthActionType.CLICK));
        }
    }

    @Nested
    class AiAuthTurnPayloadSerialization {

        @Test
        void shouldSerializeTurnPayloadWithPlaceholders() throws Exception {
            var inputElement =
                    new AiAuthInputElement(
                            "input", "email", "user", "user", "Username:", "", "", null, true);
            var payload =
                    new AiAuthTurnPayload(
                            1,
                            "http://localhost/login",
                            "Login",
                            List.of(inputElement),
                            List.of(),
                            Map.of(
                                    "username",
                                    AiAuthTurnPayload.USERNAME_PLACEHOLDER,
                                    "password",
                                    AiAuthTurnPayload.PASSWORD_PLACEHOLDER),
                            "Set domain to Project1",
                            null);

            String json = mapper.writeValueAsString(payload);

            assertThat(json, containsString("\"{{username}}\""));
            assertThat(json, containsString("\"{{password}}\""));
            assertThat(json, containsString("\"step\":1"));
            assertThat(json, containsString("\"url\":\"http://localhost/login\""));
            assertThat(json, containsString("\"userHint\":\"Set domain to Project1\""));
        }

        @Test
        void shouldSerializeSelectInputWithOptions() throws Exception {
            var selectElement =
                    new AiAuthInputElement(
                            "select",
                            null,
                            "domain",
                            "domain",
                            "Domain:",
                            "",
                            "",
                            List.of(
                                    "alpha.example.com",
                                    "beta.example.com",
                                    "Project1",
                                    "Project2"),
                            true);
            var payload =
                    new AiAuthTurnPayload(
                            1,
                            "http://localhost/login",
                            "Login",
                            List.of(selectElement),
                            List.of(),
                            Map.of(),
                            null,
                            null);

            String json = mapper.writeValueAsString(payload);

            assertThat(json, containsString("\"options\":[\"alpha.example.com\""));
            assertThat(json, containsString("\"Project1\""));
        }

        @Test
        void shouldSerializePreviousActionResults() throws Exception {
            var ok = AiAuthActionResult.ok(AiAuthActionType.SEND_KEYS, "#user", "{{username}}");
            var failed =
                    AiAuthActionResult.failed(AiAuthActionType.CLICK, "Element not found: #next");

            var payload =
                    new AiAuthTurnPayload(
                            2,
                            "http://localhost/step2",
                            "Step 2",
                            List.of(),
                            List.of(ok, failed),
                            Map.of(),
                            null,
                            null);

            String json = mapper.writeValueAsString(payload);

            assertThat(json, containsString("\"success\":true"));
            assertThat(json, containsString("\"success\":false"));
            assertThat(json, containsString("\"error\":\"Element not found: #next\""));
        }
    }

    @Nested
    class AiAuthActionResultFactoryMethods {

        @Test
        void shouldCreateSuccessfulActionResult() {
            var result = AiAuthActionResult.ok(AiAuthActionType.SEND_KEYS, "#user", "{{username}}");

            assertThat(result.type(), is(AiAuthActionType.SEND_KEYS));
            assertThat(result.usedSelector(), equalTo("#user"));
            assertThat(result.value(), equalTo("{{username}}"));
            assertThat(result.success(), is(true));
            assertThat(result.error(), nullValue());
        }

        @Test
        void shouldCreateFailedActionResult() {
            var result = AiAuthActionResult.failed(AiAuthActionType.CLICK, "Selector not found");

            assertThat(result.type(), is(AiAuthActionType.CLICK));
            assertThat(result.usedSelector(), nullValue());
            assertThat(result.value(), nullValue());
            assertThat(result.success(), is(false));
            assertThat(result.error(), equalTo("Selector not found"));
        }
    }

    @Nested
    class TerminalStates {

        @Test
        void shouldHaveExpectedPlaceholderValues() {
            assertThat(AiAuthTurnPayload.USERNAME_PLACEHOLDER, equalTo("{{username}}"));
            assertThat(AiAuthTurnPayload.PASSWORD_PLACEHOLDER, equalTo("{{password}}"));
        }

        @Test
        void shouldOnlyTreatInProgressAsNonTerminal() {
            assertThat(AiAuthState.IN_PROGRESS.name(), is("IN_PROGRESS"));
            for (AiAuthState state : AiAuthState.values()) {
                boolean expected = state != AiAuthState.IN_PROGRESS;
                var response = new AiAuthResponse(state, "", List.of(), null);
                assertThat("isTerminal for " + state, response.isTerminal(), is(expected));
            }
        }
    }
}
