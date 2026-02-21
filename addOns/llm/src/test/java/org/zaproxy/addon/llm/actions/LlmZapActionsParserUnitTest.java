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
package org.zaproxy.addon.llm.actions;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.model.HttpMessageLocation;

class LlmZapActionsParserUnitTest {

    @Test
    void shouldParseOpenRequesterActionWithInlineRequest() {
        // Given
        String assistantText =
                "Some text\n"
                        + LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\n"
                        + "      \"action\": \"open_requester_tab\",\n"
                        + "      \"location\": \"request_body\",\n"
                        + "      \"start\": 1,\n"
                        + "      \"end\": 3,\n"
                        + "      \"payload\": \"' OR 1=1 --\",\n"
                        + "      \"request\": {\n"
                        + "        \"header\": \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n\",\n"
                        + "        \"body\": \"abc\"\n"
                        + "      }\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.warnings(), is(empty()));
        assertThat(result.actions(), hasSize(1));
        LlmZapAction action = result.actions().get(0);
        assertThat(action.type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_TAB)));
        assertThat(action.historyId(), is(equalTo(-1)));
        assertThat(action.location(), is(equalTo(HttpMessageLocation.Location.REQUEST_BODY)));
        assertThat(action.start(), is(equalTo(1)));
        assertThat(action.end(), is(equalTo(3)));
        assertThat(action.payload(), is(equalTo("' OR 1=1 --")));
        assertThat(action.request(), is(not(equalTo(null))));
        assertThat(action.request().header(), containsString("GET / HTTP/1.1"));
    }

    @Test
    void shouldRejectOpenFuzzerWithoutPayloads() {
        // Given
        String assistantText =
                LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\n"
                        + "      \"action\": \"open_fuzzer\",\n"
                        + "      \"location\": \"request_header\",\n"
                        + "      \"start\": 0,\n"
                        + "      \"end\": 0,\n"
                        + "      \"history_id\": 123\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.actions(), is(empty()));
        assertThat(result.warnings(), hasSize(1));
        assertThat(result.warnings().get(0), containsString("Missing payloads"));
    }

    @Test
    void shouldParseAliasActionsAndAllowMissingContext() {
        // Given
        String assistantText =
                LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\n"
                        + "      \"action\": \"open_request_editor\",\n"
                        + "      \"payload\": \"' OR 1=1 --\"\n"
                        + "    },\n"
                        + "    {\n"
                        + "      \"action\": \"open_requester\",\n"
                        + "      \"payload\": \"' OR 1=1 --\"\n"
                        + "    },\n"
                        + "    {\n"
                        + "      \"action\": \"open_http_fuzzer\",\n"
                        + "      \"payloads\": [\"a\", \"b\"]\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.actions(), hasSize(3));
        assertThat(result.actions().get(0).type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_DIALOG)));
        assertThat(result.actions().get(1).type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_TAB)));
        assertThat(result.actions().get(2).type(), is(equalTo(LlmZapActionType.OPEN_FUZZER)));

        // Missing context should be allowed for parsing (filled by caller if needed).
        assertThat(result.actions().get(0).historyId(), is(equalTo(-1)));
        assertThat(result.actions().get(0).request(), is(equalTo(null)));
        assertThat(result.actions().get(0).location(), is(equalTo(null)));
        assertThat(result.actions().get(0).start(), is(equalTo(-1)));
        assertThat(result.actions().get(0).end(), is(equalTo(-1)));

        assertThat(result.actions().get(2).payloads(), is(equalTo(List.of("a", "b"))));
    }

    @Test
    void shouldParseActionsWhenJsonIsWrappedInCodeFences() {
        // Given
        String assistantText =
                "Explanation...\n"
                        + LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n```json\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\"action\": \"open_requester\", \"payload\": \"x\"}\n"
                        + "  ]\n"
                        + "}\n"
                        + "```\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.warnings(), is(empty()));
        assertThat(result.actions(), hasSize(1));
        assertThat(result.actions().get(0).type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_TAB)));
    }

    @Test
    void shouldParseActionsWhenJsonIsEmbeddedWithoutMarkers() {
        // Given
        String assistantText =
                "Some header...\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\"action\": \"open_fuzzer\", \"payloads\": [\"a\"]}\n"
                        + "  ]\n"
                        + "}\n"
                        + "Some footer...";

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.actions(), hasSize(1));
        assertThat(result.actions().get(0).type(), is(equalTo(LlmZapActionType.OPEN_FUZZER)));
    }

    @Test
    void shouldParseActionsWhenArrayItemsUseMarkdownBullets() {
        // Given
        String assistantText =
                LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    * {\"action\": \"open_requester\", \"payload\": \"x\"},\n"
                        + "    - {\"action\": \"open_http_fuzzer\", \"payloads\": [\"a\"]}\n"
                        + "  ]\n"
                        + "}\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.warnings(), is(empty()));
        assertThat(result.actions(), hasSize(2));
        assertThat(result.actions().get(0).type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_TAB)));
        assertThat(result.actions().get(1).type(), is(equalTo(LlmZapActionType.OPEN_FUZZER)));
    }

    @Test
    void shouldParseActionsWhenActionIdUsesAlternativeFieldName() {
        // Given
        String assistantText =
                LlmZapActionsParser.ACTIONS_BEGIN
                        + "\n"
                        + "{\n"
                        + "  \"actions\": [\n"
                        + "    {\"type\": \"open_requester\", \"payload\": \"x\"},\n"
                        + "    {\"id\": \"open_http_fuzzer\", \"payloads\": [\"a\"]}\n"
                        + "  ]\n"
                        + "}\n"
                        + LlmZapActionsParser.ACTIONS_END;

        // When
        LlmZapActionsParseResult result = new LlmZapActionsParser().parse(assistantText);

        // Then
        assertThat(result.warnings(), is(empty()));
        assertThat(result.actions(), hasSize(2));
        assertThat(result.actions().get(0).type(), is(equalTo(LlmZapActionType.OPEN_REQUESTER_TAB)));
        assertThat(result.actions().get(1).type(), is(equalTo(LlmZapActionType.OPEN_FUZZER)));
    }
}
