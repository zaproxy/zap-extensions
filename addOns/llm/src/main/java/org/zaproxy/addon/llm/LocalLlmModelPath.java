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
package org.zaproxy.addon.llm;

import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;

/**
 * Resolves local SafeTensors model directories under the ZAP home {@link
 * LlmProvider#LOCAL_MODELS_DIR} directory.
 *
 * <p>Accepts absolute paths, bare folder names, and HuggingFace {@code owner/name} ids (mapped to
 * {@code owner_name} folders). Persisted configs store the absolute directory path; the UI shows
 * only the last path segment.
 */
public final class LocalLlmModelPath {

    private LocalLlmModelPath() {}

    /**
     * Returns {@code <zapHome>/llm-models}.
     *
     * @return the models directory under the ZAP home
     */
    public static Path getModelsDirectory() {
        return Path.of(Constant.getZapHome(), LlmProvider.LOCAL_MODELS_DIR);
    }

    /**
     * Resolves a configured model id to a local directory. Absolute paths are used as-is; {@code
     * owner/name} ids resolve to {@code llm-models/owner_name}; bare names resolve under {@link
     * #getModelsDirectory()}.
     *
     * @param model the configured model id or path
     * @return the normalised absolute model directory
     */
    public static Path resolveModelDirectory(String model) {
        String trimmed = StringUtils.trimToEmpty(model);
        Path path = Path.of(trimmed);
        if (path.isAbsolute()) {
            return normalizeAbsolute(path);
        }

        String normalized = trimmed.replace('\\', '/');
        if (normalized.contains("/")) {
            String[] parts = normalized.split("/", 2);
            if (parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
                return getModelsDirectory()
                        .resolve(parts[0] + "_" + parts[1])
                        .toAbsolutePath()
                        .normalize();
            }
        }

        Path fileName = path.getFileName();
        return getModelsDirectory()
                .resolve(fileName != null ? fileName : path)
                .toAbsolutePath()
                .normalize();
    }

    /**
     * Returns the absolute directory path to store in provider config for a user-entered model path
     * or id.
     *
     * @param model the user-entered model id or path
     * @return the absolute path to persist, or empty when {@code model} is blank
     */
    public static String toStoredModelId(String model) {
        String trimmed = StringUtils.trimToEmpty(model);
        if (trimmed.isEmpty()) {
            return trimmed;
        }
        return resolveModelDirectory(trimmed).toString();
    }

    /**
     * Returns a short UI label for a configured model path or id (the last path segment).
     *
     * @param model the configured model id or path
     * @return the display name
     */
    public static String toDisplayName(String model) {
        String trimmed = StringUtils.trimToEmpty(model);
        if (trimmed.isEmpty()) {
            return trimmed;
        }
        Path name = resolveModelDirectory(trimmed).getFileName();
        return name == null ? trimmed : name.toString();
    }

    /**
     * Returns {@code true} if the path resolves to a directory containing {@code config.json}.
     *
     * @param path the user-supplied path or model id
     * @return {@code true} if the path looks like a local SafeTensors model directory
     */
    public static boolean isValidModelDirectory(String path) {
        Path resolved = resolveModelDirectory(path);
        return Files.isDirectory(resolved) && Files.exists(resolved.resolve("config.json"));
    }

    private static Path normalizeAbsolute(Path path) {
        Path resolved = path.toAbsolutePath().normalize();
        if (Files.isRegularFile(resolved)) {
            Path parent = resolved.getParent();
            if (parent != null) {
                return parent;
            }
        }
        return resolved;
    }
}
