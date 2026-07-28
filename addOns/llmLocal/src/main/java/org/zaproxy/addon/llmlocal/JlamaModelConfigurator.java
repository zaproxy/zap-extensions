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

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.LlmProviderConfig;
import org.zaproxy.addon.llm.LocalLlmModelPath;

/**
 * Downloads a HuggingFace model under the ZAP home {@code llm-models} directory and configures it
 * as the default local LLM provider (Jlama).
 */
public final class JlamaModelConfigurator {

    static final String PROVIDER_NAME = "Local";

    private JlamaModelConfigurator() {}

    /**
     * Returns {@code <zapHome>/llm-models}.
     *
     * @return the models directory under the ZAP home
     */
    public static Path getModelsDirectory() {
        return JlamaModelPath.getModelsDirectory();
    }

    /**
     * Downloads {@code ownerSlashName} into {@link #getModelsDirectory()} and configures it as the
     * default local LLM provider in the LLM add-on.
     *
     * @param extensionLlm the LLM extension
     * @param ownerSlashName HuggingFace model id ({@code owner/name})
     * @return the local model directory
     * @throws IOException if the download fails
     */
    public static Path downloadAndConfigure(ExtensionLlm extensionLlm, String ownerSlashName)
            throws IOException {
        Path modelDir = JlamaModelDownloader.download(getModelsDirectory(), ownerSlashName);
        configureProvider(extensionLlm, modelDir);
        return modelDir;
    }

    static void configureProvider(ExtensionLlm extensionLlm, Path modelDir) {
        String modelId = LocalLlmModelPath.toStoredModelId(modelDir.toString());
        LlmProviderConfig config =
                new LlmProviderConfig(PROVIDER_NAME, LlmProvider.JLAMA, "", "", List.of(modelId));
        extensionLlm.configureProvider(config, true);
    }
}
