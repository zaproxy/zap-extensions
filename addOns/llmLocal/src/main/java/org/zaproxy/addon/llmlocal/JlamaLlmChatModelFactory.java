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

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.listener.ChatModelListener;
import dev.langchain4j.model.jlama.JlamaChatModel;
import java.nio.file.Path;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.llm.LlmChatModelFactory;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;

/**
 * Creates in-process {@link JlamaChatModel} instances from a local SafeTensors model directory
 * path.
 */
public class JlamaLlmChatModelFactory implements LlmChatModelFactory {

    private static final Logger LOGGER = LogManager.getLogger(JlamaLlmChatModelFactory.class);

    private static final float DEFAULT_TEMPERATURE = 0.3f;

    @Override
    public LlmProvider getProvider() {
        return LlmProvider.JLAMA;
    }

    @Override
    public ChatModel create(
            LlmProviderConfig config,
            String modelName,
            ChatModelListener listener,
            boolean withJsonResponseFormat) {
        Path modelDir = JlamaModelPath.resolveModelDirectory(modelName);
        if (!JlamaModelPath.isValidModelDirectory(modelName)) {
            throw new IllegalArgumentException(
                    Constant.messages.getString("llmlocal.error.model.path", modelName));
        }
        if (!JlamaRuntime.isVectorApiAvailable()) {
            throw new IllegalStateException(Constant.messages.getString("llmlocal.error.vector.api"));
        }

        // JlamaChatModel expects HuggingFace owner/name; local folders are owner_name.
        String jlamaModelId = JlamaModelPath.toJlamaModelId(modelName);
        Path modelCachePath = modelDir.getParent();

        if (!JlamaModelPath.supportsTools(modelName)) {
            LOGGER.warn(
                    "Jlama model {} does not appear to support tools in its chat template. "
                            + "MCP / ZAP tools will not be visible to this model. Prefer a "
                            + "tool-capable Instruct model such as tjake/Llama-3.2-1B-Instruct-Jlama-Q4 "
                            + "or tjake/granite-3.0-2b-instruct-JQ4.",
                    modelDir.getFileName());
        }

        if (withJsonResponseFormat) {
            LOGGER.debug(
                    "JSON response format requested for Jlama model {} but is not supported; ignoring.",
                    modelDir);
        }
        if (listener != null) {
            LOGGER.debug(
                    "ChatModelListener provided for Jlama model {} but JlamaChatModel does not support listeners.",
                    modelDir);
        }

        try {
            ChatModel model =
                    JlamaRuntime.withAddOnClassLoader(
                            () ->
                                    JlamaChatModel.builder()
                                            .modelCachePath(modelCachePath)
                                            .modelName(jlamaModelId)
                                            .temperature(DEFAULT_TEMPERATURE)
                                            .build());
            // Chat (prompt template rendering via Jinjava) also needs the add-on classloader.
            return new JlamaClassLoaderAwareChatModel(model);
        } catch (RuntimeException e) {
            LOGGER.error("Failed to load Jlama model from {}", modelDir, e);
            throw new IllegalStateException(
                    Constant.messages.getString(
                            "llmlocal.error.model.load", modelDir, JlamaRuntime.rootCauseMessage(e)),
                    e);
        }
    }
}
