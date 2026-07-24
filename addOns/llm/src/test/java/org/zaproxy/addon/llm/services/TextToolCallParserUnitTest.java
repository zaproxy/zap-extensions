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
package org.zaproxy.addon.llm.services;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TextToolCallParserUnitTest {

    @Test
    void shouldParseSimpleToolCallJson() {
        Optional<ToolExecutionRequest> parsed =
                TextToolCallParser.tryParse(
                        """
                        {
                          "name": "zap_info",
                          "arguments": {}
                        }
                        """);

        assertThat(parsed.isPresent(), is(true));
        assertThat(parsed.get().name(), is("zap_info"));
        assertThat(parsed.get().arguments(), is("{}"));
    }

    @Test
    void shouldParseToolCallWithParametersAndCodeFence() {
        Optional<ToolExecutionRequest> parsed =
                TextToolCallParser.tryParse(
                        """
                        ```json
                        {"name":"start_spider","parameters":{"url":"https://example.com"}}
                        ```
                        """);

        assertThat(parsed.isPresent(), is(true));
        assertThat(parsed.get().name(), is("start_spider"));
        assertThat(parsed.get().arguments(), is("{\"url\":\"https://example.com\"}"));
    }

    @Test
    void shouldParseToolCallEmbeddedInProseAndCodeFence() {
        Optional<ToolExecutionRequest> parsed =
                TextToolCallParser.tryParse(
                        """
                        To check if the spider has finished, I will call the `zap_get_spider_status` function.

                        ```json
                        {"name": "zap_get_spider_status", "arguments": {"scan_id":"spider-0"}}
                        ```
                        """);

        assertThat(parsed.isPresent(), is(true));
        assertThat(parsed.get().name(), is("zap_get_spider_status"));
        assertThat(parsed.get().arguments(), is("{\"scan_id\":\"spider-0\"}"));
    }

    @Test
    void shouldParseToolCallEmbeddedInProseWithoutFence() {
        Optional<ToolExecutionRequest> parsed =
                TextToolCallParser.tryParse(
                        """
                        I will check the status again.
                        {"name":"zap_get_spider_status","arguments":{"scan_id":"spider-0"}}
                        """);

        assertThat(parsed.isPresent(), is(true));
        assertThat(parsed.get().name(), is("zap_get_spider_status"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Hello, I am an assistant.",
                "{\"greeting\":\"hi\"}",
                "{\"name\":\"zap_info\",\"arguments\":{},\"extra\":true}",
                ""
            })
    void shouldIgnoreNonToolCallText(String text) {
        assertThat(TextToolCallParser.tryParse(text).isPresent(), is(false));
    }
}
