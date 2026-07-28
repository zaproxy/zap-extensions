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
package org.zaproxy.addon.llmlocal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.jupiter.api.Assertions.assertThrows;

import dev.langchain4j.agent.tool.ToolSpecification;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class JlamaClassLoaderAwareChatModelUnitTest {

    @Test
    void doChatShouldRunWithAddOnClassLoader() {
        ClassLoader addOnLoader = JlamaRuntime.class.getClassLoader();
        ClassLoader[] seen = new ClassLoader[1];
        ChatModel delegate =
                new ChatModel() {
                    @Override
                    public ChatResponse doChat(ChatRequest chatRequest) {
                        seen[0] = Thread.currentThread().getContextClassLoader();
                        return ChatResponse.builder().aiMessage(AiMessage.from("ok")).build();
                    }
                };

        ChatModel wrapper = new JlamaClassLoaderAwareChatModel(delegate);
        ClassLoader previous = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(ClassLoader.getSystemClassLoader());
            ChatResponse response =
                    wrapper.chat(
                            ChatRequest.builder()
                                    .messages(UserMessage.from("hello"))
                                    .build());
            assertThat(response.aiMessage().text(), is("ok"));
            assertThat(seen[0], is(sameInstance(addOnLoader)));
        } finally {
            Thread.currentThread().setContextClassLoader(previous);
        }
    }

    @Test
    void shouldRetryWithoutToolsWhenToolCallNameSortFails() {
        AtomicInteger calls = new AtomicInteger();
        ChatModel delegate =
                new ChatModel() {
                    @Override
                    public ChatResponse doChat(ChatRequest chatRequest) {
                        int call = calls.incrementAndGet();
                        var tools = chatRequest.parameters().toolSpecifications();
                        if (call == 1) {
                            assertThat(tools == null || tools.isEmpty(), is(false));
                            throw new RuntimeException(
                                    new NullPointerException(
                                            "Cannot invoke \"java.lang.Comparable.compareTo(Object)\" because the return value of \"java.util.function.Function.apply(Object)\" is null"));
                        }
                        assertThat(tools == null || tools.isEmpty(), is(true));
                        return ChatResponse.builder()
                                .aiMessage(AiMessage.from("listed tools in prose"))
                                .build();
                    }
                };

        ChatResponse response =
                new JlamaClassLoaderAwareChatModel(delegate)
                        .chat(
                                ChatRequest.builder()
                                        .messages(UserMessage.from("what tools?"))
                                        .toolSpecifications(
                                                ToolSpecification.builder()
                                                        .name("zap_start_spider")
                                                        .build())
                                        .build());

        assertThat(response.aiMessage().text(), is("listed tools in prose"));
        assertThat(calls.get(), is(2));
    }

    @Test
    void shouldNotRetryWhenFailureIsUnrelated() {
        ChatModel delegate =
                new ChatModel() {
                    @Override
                    public ChatResponse doChat(ChatRequest chatRequest) {
                        throw new IllegalStateException("boom");
                    }
                };

        assertThrows(
                IllegalStateException.class,
                () ->
                        new JlamaClassLoaderAwareChatModel(delegate)
                                .chat(
                                        ChatRequest.builder()
                                                .messages(UserMessage.from("hi"))
                                                .toolSpecifications(
                                                        ToolSpecification.builder()
                                                                .name("zap_info")
                                                                .build())
                                                .build()));
    }

    @Test
    void shouldDetectToolCallNameSortFailure() {
        assertThat(
                JlamaClassLoaderAwareChatModel.isToolCallNameSortFailure(
                        new RuntimeException(
                                new NullPointerException(
                                        "Cannot invoke \"java.lang.Comparable.compareTo(Object)\" because the return value of \"java.util.function.Function.apply(Object)\" is null"))),
                is(true));
        assertThat(
                JlamaClassLoaderAwareChatModel.isToolCallNameSortFailure(
                        new NullPointerException("something else")),
                is(false));
    }
}
