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
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.service.tool.ToolProvider;
import dev.langchain4j.service.tool.ToolProviderResult;
import java.util.List;
import org.junit.jupiter.api.Test;

class TextToolCallNormalizingChatModelUnitTest {

    @Test
    void shouldRewriteKnownTextToolCall() {
        ChatModel delegate = mock(ChatModel.class);
        ToolProvider toolProvider = mock(ToolProvider.class);
        given(toolProvider.provideTools(any()))
                .willReturn(
                        ToolProviderResult.builder()
                                .add(
                                        ToolSpecification.builder().name("zap_info").build(),
                                        (req, mem) -> "ok")
                                .build());
        given(delegate.chat(any(ChatRequest.class)))
                .willReturn(
                        ChatResponse.builder()
                                .aiMessage(
                                        AiMessage.from("{\"name\":\"zap_info\",\"arguments\":{}}"))
                                .build());

        ChatModel model = new TextToolCallNormalizingChatModel(delegate, List.of(toolProvider));
        ChatResponse response =
                model.chat(
                        ChatRequest.builder()
                                .messages(UserMessage.from("what is your name?"))
                                .build());

        assertThat(response.aiMessage().hasToolExecutionRequests(), is(true));
        assertThat(response.aiMessage().toolExecutionRequests().get(0).name(), is("zap_info"));
        assertThat(response.aiMessage().text(), is(nullValue()));
    }

    @Test
    void shouldLeaveUnknownTextToolCallUnchanged() {
        ChatModel delegate = mock(ChatModel.class);
        ToolProvider toolProvider = mock(ToolProvider.class);
        given(toolProvider.provideTools(any())).willReturn(ToolProviderResult.builder().build());
        String text = "{\"name\":\"zap_info\",\"arguments\":{}}";
        given(delegate.chat(any(ChatRequest.class)))
                .willReturn(ChatResponse.builder().aiMessage(AiMessage.from(text)).build());

        ChatModel model = new TextToolCallNormalizingChatModel(delegate, List.of(toolProvider));
        ChatResponse response =
                model.chat(
                        ChatRequest.builder()
                                .messages(UserMessage.from("what is your name?"))
                                .build());

        assertThat(response.aiMessage().hasToolExecutionRequests(), is(false));
        assertThat(response.aiMessage().text(), is(text));
    }
}
