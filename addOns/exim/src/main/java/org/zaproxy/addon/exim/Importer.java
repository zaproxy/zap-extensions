/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;
import org.zaproxy.addon.exim.har.HarImporterType;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

/**
 * Importer of data (e.g. HAR, pluggable formats).
 *
 * @since 0.13.0
 * @see ExtensionExim#getImporter()
 */
public class Importer {

    private static final Map<String, ImporterType> REGISTERED_TYPES =
            Collections.synchronizedMap(new LinkedHashMap<>());

    private static final Exception STOP_IMPORT_EXCEPTION =
            new Exception() {
                private static final long serialVersionUID = 1L;

                @Override
                public synchronized Throwable fillInStackTrace() {
                    return this;
                }
            };

    Importer() {}

    static void register(ImporterType importerType) {
        if (importerType != null
                && importerType.getId() != null
                && !importerType.getId().isBlank()) {
            REGISTERED_TYPES.put(importerType.getId().toLowerCase(Locale.ROOT), importerType);
        }
    }

    static void unregister(String typeId) {
        if (typeId != null) {
            REGISTERED_TYPES.remove(typeId.toLowerCase(Locale.ROOT));
        }
    }

    /**
     * Gets the importer type for the given type ID.
     *
     * @param typeId the import type identifier.
     * @return the importer type, or {@code null} if not found.
     * @since 0.18.0
     */
    public static ImporterType getImporterType(String typeId) {
        return typeId != null ? REGISTERED_TYPES.get(typeId.toLowerCase(Locale.ROOT)) : null;
    }

    /**
     * Returns all available import types (built-in and registered).
     *
     * @return the list of importer types.
     * @since 0.18.0
     */
    public static List<ImporterType> getAvailableTypes() {
        return new ArrayList<>(REGISTERED_TYPES.values());
    }

    /**
     * Resolves a type string to an importer type.
     *
     * @param value the type identifier.
     * @return the importer type, or the default (HAR) if not found.
     * @since 0.18.0
     */
    public static ImporterType fromString(String value) {
        if (value == null || value.isBlank()) {
            return getImporterType(HarImporterType.ID);
        }
        ImporterType type = getImporterType(value);
        return type != null ? type : getImporterType(HarImporterType.ID);
    }

    /**
     * Imports the data with the given options.
     *
     * @param options the importer options.
     * @return the result of the import.
     */
    public ImporterResult apply(ImporterOptions options) {
        ImporterResult result = importImpl(options);
        String typeId =
                options.getType() != null
                        ? options.getType().toLowerCase(Locale.ROOT)
                        : HarImporterType.ID;
        Stats.incCounter(
                ExtensionExim.STATS_PREFIX + "importer." + typeId + ".count", result.getCount());
        return result;
    }

    private static ImporterResult importImpl(ImporterOptions options) {
        ImporterResult result = new ImporterResult();
        Path file = options.getInputFile();
        if (!isValid(file, result)) {
            return result;
        }

        try (var reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {

            ImporterType type = createImporterType(options);
            if (type == null) {
                result.addError(
                        Constant.messages.getString(
                                "exim.importer.error.type.unavailable", options.getType()));
                return result;
            }

            MessageHandler messageHandler = options.getMessageHandler();
            Context context = options.getContext();

            type.importData(
                    reader,
                    msg -> {
                        if (context != null
                                && !context.isInContext(
                                        msg.getRequestHeader().getURI().toString())) {
                            return;
                        }

                        try {
                            messageHandler.handle(msg);
                            result.incrementCount();
                        } catch (Exception e) {
                            result.addError(
                                    Constant.messages.getString(
                                            "exim.importer.error.handler", e.getLocalizedMessage()),
                                    e);
                            throw STOP_IMPORT_EXCEPTION;
                        }
                    });
        } catch (Exception e) {
            if (e != STOP_IMPORT_EXCEPTION) {
                result.addError(
                        Constant.messages.getString(
                                "exim.importer.error.io", e.getLocalizedMessage()),
                        e);
            }
        }

        return result;
    }

    private static boolean isValid(Path file, ImporterResult result) {
        if (Files.notExists(file)) {
            result.addError(
                    Constant.messages.getString("exim.importer.error.file.notexists", file));
            return false;
        }

        if (!Files.isRegularFile(file)) {
            result.addError(Constant.messages.getString("exim.importer.error.file.notfile", file));
            return false;
        }

        if (!Files.isReadable(file)) {
            result.addError(
                    Constant.messages.getString("exim.importer.error.file.notreadable", file));
            return false;
        }

        return true;
    }

    private static ImporterType createImporterType(ImporterOptions options) {
        String typeId = options.getType();
        if (typeId == null || typeId.isBlank()) {
            return getImporterType(HarImporterType.ID);
        }
        return getImporterType(typeId);
    }
}
