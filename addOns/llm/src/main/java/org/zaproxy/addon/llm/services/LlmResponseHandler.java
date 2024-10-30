package org.zaproxy.addon.llm.services;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.output.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import dev.langchain4j.model.chat.listener.ChatModelResponse;
import dev.langchain4j.model.chat.listener.ChatModelRequest;
import dev.langchain4j.model.chat.listener.ChatModelRequestContext;
import dev.langchain4j.model.chat.listener.ChatModelResponseContext;
import dev.langchain4j.model.chat.listener.ChatModelErrorContext;

import java.util.Map;

public class LlmResponseHandler implements ChatModelListener {

    private static final Logger LOGGER = LogManager.getLogger(LlmResponseHandler.class);

    @Override
    public void onRequest(ChatModelRequestContext requestContext) {
        ChatModelRequest request = requestContext.request();
        Map<Object, Object> attributes = requestContext.attributes();
    }

    @Override
    public void onResponse(ChatModelResponseContext responseContext) {
        ChatModelResponse response = responseContext.response();
        ChatModelRequest request = responseContext.request();
        Map<Object, Object> attributes = responseContext.attributes();
        LOGGER.info("Token usage = " + response.tokenUsage());
    }

    @Override
    public void onError(ChatModelErrorContext errorContext) {
        Throwable error = errorContext.error();
        ChatModelRequest request = errorContext.request();
        ChatModelResponse partialResponse = errorContext.partialResponse();
        Map<Object, Object> attributes = errorContext.attributes();
        LOGGER.error("LLM/AI Error : " + error);
        throw new RuntimeException("LLM/AI Error : " + error.getMessage());
    }
}