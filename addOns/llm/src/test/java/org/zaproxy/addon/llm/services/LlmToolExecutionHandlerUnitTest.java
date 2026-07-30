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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.service.tool.BeforeToolExecution;
import dev.langchain4j.service.tool.ToolExecution;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.ui.LlmChatTabPanel;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link LlmToolExecutionHandler}. */
class LlmToolExecutionHandlerUnitTest extends TestUtils {

    @BeforeAll
    static void beforeAll() {
        mockMessages(new ExtensionLlm());
    }

    @Test
    void shouldAppendToolCallBeforeExecution() {
        // Given
        LlmChatTabPanel chatPanel = mock(LlmChatTabPanel.class);
        LlmToolExecutionHandler handler = new LlmToolExecutionHandler(chatPanel);
        BeforeToolExecution before = mock(BeforeToolExecution.class);
        given(before.request())
                .willReturn(
                        ToolExecutionRequest.builder()
                                .name("zap_info")
                                .arguments("{\"verbose\":\"true\"}")
                                .build());

        // When
        handler.beforeToolExecution(before);

        // Then
        verify(chatPanel)
                .appendIntermediateMessage(
                        eq(LlmChatTabPanel.TOOL_CALL_LABEL),
                        eq("zap_info\n{\"verbose\":\"true\"}"));
    }

    @Test
    void shouldDefaultBlankArgumentsToEmptyJsonObject() {
        // Given
        LlmChatTabPanel chatPanel = mock(LlmChatTabPanel.class);
        LlmToolExecutionHandler handler = new LlmToolExecutionHandler(chatPanel);
        BeforeToolExecution before = mock(BeforeToolExecution.class);
        given(before.request())
                .willReturn(
                        ToolExecutionRequest.builder().name("zap_version").arguments("").build());

        // When
        handler.beforeToolExecution(before);

        // Then
        verify(chatPanel)
                .appendIntermediateMessage(
                        eq(LlmChatTabPanel.TOOL_CALL_LABEL), eq("zap_version\n{}"));
    }

    @Test
    void shouldAppendToolResultAfterExecution() {
        // Given
        LlmChatTabPanel chatPanel = mock(LlmChatTabPanel.class);
        LlmToolExecutionHandler handler = new LlmToolExecutionHandler(chatPanel);
        ToolExecution execution = mock(ToolExecution.class);
        given(execution.request())
                .willReturn(
                        ToolExecutionRequest.builder().name("zap_version").arguments("{}").build());
        given(execution.result()).willReturn("2.16.0");

        // When
        handler.afterToolExecution(execution);

        // Then
        verify(chatPanel)
                .appendIntermediateMessage(
                        eq(LlmChatTabPanel.TOOL_RESULT_LABEL), eq("zap_version\n2.16.0"));
    }

    @Test
    void shouldFailToCreateWithNullChatPanel() {
        // Given / When / Then
        assertThrows(NullPointerException.class, () -> new LlmToolExecutionHandler(null));
    }
}
