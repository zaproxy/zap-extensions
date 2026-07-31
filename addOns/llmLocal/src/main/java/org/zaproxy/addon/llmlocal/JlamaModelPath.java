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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LocalLlmModelPath;

/** Helpers for resolving local Jlama SafeTensors model directories. */
public final class JlamaModelPath {

    private static final Logger LOGGER = LogManager.getLogger(JlamaModelPath.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static final String MODELS_DIR_NAME = LlmProvider.LOCAL_MODELS_DIR;

    private JlamaModelPath() {}

    /**
     * Returns {@code <zapHome>/llm-models}.
     *
     * @return the models directory under the ZAP home
     */
    public static Path getModelsDirectory() {
        return LocalLlmModelPath.getModelsDirectory();
    }

    /**
     * Returns a short UI label for a configured model id.
     *
     * @param modelDir the model directory
     * @return the last path segment
     */
    public static String toModelName(Path modelDir) {
        Path name = modelDir.getFileName();
        return name == null ? modelDir.toString() : name.toString();
    }

    /**
     * Converts a configured model id to the HuggingFace {@code owner/name} form expected by {@code
     * JlamaChatModel}. Local download folders use {@code owner_name}; that is mapped back to {@code
     * owner/name}.
     *
     * @param model the configured model id, folder name, or path
     * @return a Jlama/HuggingFace model id
     */
    public static String toJlamaModelId(String model) {
        String trimmed = StringUtils.trimToEmpty(model);
        if (trimmed.isEmpty()) {
            return trimmed;
        }
        Path path = Path.of(trimmed);
        String name = path.isAbsolute() ? toModelName(path) : trimmed.replace('\\', '/');
        if (name.contains("/")) {
            return name;
        }
        int separator = name.indexOf('_');
        if (separator > 0 && separator < name.length() - 1) {
            return name.substring(0, separator) + "/" + name.substring(separator + 1);
        }
        return name;
    }

    /**
     * Resolves a configured model id to a local directory.
     *
     * @param model the configured model id or path
     * @return the normalised absolute model directory
     */
    public static Path resolveModelDirectory(String model) {
        return LocalLlmModelPath.resolveModelDirectory(model);
    }

    /**
     * Normalises a user-supplied absolute path to a model directory.
     *
     * @param path the user-supplied path
     * @return the normalised absolute path
     */
    public static Path normalize(String path) {
        return LocalLlmModelPath.resolveModelDirectory(path);
    }

    /**
     * Returns {@code true} if the path resolves to a directory containing {@code config.json}.
     *
     * @param path the user-supplied path or model id
     * @return {@code true} if the path looks like a local SafeTensors model directory
     */
    public static boolean isValidModelDirectory(String path) {
        return LocalLlmModelPath.isValidModelDirectory(path);
    }

    /**
     * Returns {@code true} when the model's HuggingFace chat template mentions tools. Jlama only
     * injects tool definitions into the prompt for models whose template supports them (for example
     * Llama 3.2 Instruct). Models such as TinyLlama have no tool section and will never see MCP
     * tools even when ZAP includes them in the request.
     *
     * @param model the configured model id or path
     * @return {@code true} if the chat template appears to support tools
     */
    public static boolean supportsTools(String model) {
        Path tokenizerConfig = resolveModelDirectory(model).resolve("tokenizer_config.json");
        if (!Files.isRegularFile(tokenizerConfig)) {
            return false;
        }
        try {
            JsonNode root = OBJECT_MAPPER.readTree(tokenizerConfig.toFile());
            JsonNode chatTemplate = root.get("chat_template");
            if (chatTemplate == null || !chatTemplate.isTextual()) {
                return false;
            }
            return chatTemplate.asText().toLowerCase().contains("tool");
        } catch (Exception e) {
            LOGGER.debug("Could not read chat template from {}", tokenizerConfig, e);
            return false;
        }
    }
}
