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

import com.github.tjake.jlama.util.Downloader;
import com.github.tjake.jlama.util.ProgressReporter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Objects;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Downloads HuggingFace SafeTensors models for local Jlama use (for example automated tests).
 *
 * <p>Auth token resolution is handled by Jlama ({@code HF_TOKEN} / {@code huggingface.auth.token}).
 */
public final class JlamaModelDownloader {

    private static final Logger LOGGER = LogManager.getLogger(JlamaModelDownloader.class);

    /** Written by Jlama when a HuggingFace model download has completed successfully. */
    static final String FINISHED_MARKER = ".finished";

    /** Small pre-quantized chat model suitable for automated tests. */
    /** Default download suggestion: Instruct model with chat-template tool support. */
    public static final String DEFAULT_TEST_MODEL = "tjake/Llama-3.2-1B-Instruct-Jlama-Q4";

    private JlamaModelDownloader() {}

    /**
     * Downloads {@link #DEFAULT_TEST_MODEL} into {@code cacheDir}, or returns the existing cached
     * path.
     *
     * @param cacheDir directory that holds downloaded models
     * @return the local model directory
     * @throws IOException if the download fails
     */
    public static Path downloadDefaultTestModel(Path cacheDir) throws IOException {
        return download(cacheDir, DEFAULT_TEST_MODEL);
    }

    /**
     * Downloads a HuggingFace model in {@code owner/name} form into {@code cacheDir}, or returns
     * the existing cached path.
     *
     * @param cacheDir directory that holds downloaded models
     * @param ownerSlashName HuggingFace model id, for example {@code tjake/TinyLlama-...}
     * @return the local model directory
     * @throws IOException if the download fails
     */
    public static Path download(Path cacheDir, String ownerSlashName) throws IOException {
        return download(cacheDir, ownerSlashName, null);
    }

    /**
     * Downloads a HuggingFace model in {@code owner/name} form into {@code cacheDir}, or returns
     * the existing cached path.
     *
     * @param cacheDir directory that holds downloaded models
     * @param ownerSlashName HuggingFace model id, for example {@code tjake/TinyLlama-...}
     * @param progressReporter optional progress callback (may throw to abort the download)
     * @return the local model directory
     * @throws IOException if the download fails
     */
    public static Path download(
            Path cacheDir, String ownerSlashName, ProgressReporter progressReporter)
            throws IOException {
        Objects.requireNonNull(cacheDir, "cacheDir");
        String model = StringUtils.trimToEmpty(ownerSlashName);
        validateModelId(model);

        Files.createDirectories(cacheDir);
        LOGGER.info("Downloading Jlama model {} into {}", model, cacheDir.toAbsolutePath());

        Downloader downloader = new Downloader(cacheDir.toAbsolutePath().toString(), model);
        if (progressReporter != null) {
            downloader = downloader.withProgressReporter(progressReporter);
        }

        Path modelDir = downloader.huggingFaceModel().toPath().toAbsolutePath().normalize();

        if (!JlamaModelPath.isValidModelDirectory(modelDir.toString())) {
            throw new IOException(
                    "Downloaded model is not a valid SafeTensors directory: " + modelDir);
        }
        return modelDir;
    }

    /**
     * Deletes {@code modelDir} when it looks like an incomplete HuggingFace download (no {@link
     * #FINISHED_MARKER}). Complete models are left untouched.
     *
     * @param modelDir the local model directory
     */
    public static void deleteIncompleteDownload(Path modelDir) {
        if (modelDir == null || !Files.isDirectory(modelDir)) {
            return;
        }
        if (Files.exists(modelDir.resolve(FINISHED_MARKER))) {
            LOGGER.debug("Leaving complete model directory in place: {}", modelDir);
            return;
        }
        LOGGER.info("Deleting incomplete Jlama model download at {}", modelDir);
        try (Stream<Path> walk = Files.walk(modelDir)) {
            walk.sorted(Comparator.reverseOrder())
                    .forEach(
                            path -> {
                                try {
                                    Files.deleteIfExists(path);
                                } catch (IOException e) {
                                    LOGGER.warn(
                                            "Failed to delete incomplete download file {}: {}",
                                            path,
                                            e.getMessage());
                                }
                            });
        } catch (IOException e) {
            LOGGER.warn(
                    "Failed to delete incomplete download directory {}: {}",
                    modelDir,
                    e.getMessage());
        }
    }

    public static void validateModelId(String ownerSlashName) {
        String model = StringUtils.trimToEmpty(ownerSlashName);
        if (model.isEmpty()) {
            throw new IllegalArgumentException("Model must be in the form owner/name");
        }
        String[] parts = model.split("/", -1);
        if (parts.length == 0 || parts.length > 2) {
            throw new IllegalArgumentException("Model must be in the form owner/name");
        }
        for (String part : parts) {
            if (part.isEmpty()) {
                throw new IllegalArgumentException("Model must be in the form owner/name");
            }
        }
    }
}
