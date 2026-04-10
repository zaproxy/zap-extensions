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

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.har.HarExporter;
import org.zaproxy.addon.exim.sites.SitesTreeHandler;
import org.zaproxy.addon.exim.sites.YamlExporter;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

/**
 * Exporter of data (e.g. HAR, URLs).
 *
 * @since 0.13.0
 * @see ExtensionExim#getExporter()
 */
public class Exporter {

    private static final Map<String, ExporterType> REGISTERED_TYPES =
            Collections.synchronizedMap(new LinkedHashMap<>());

    private static final Map<ExporterOptions.Source, SourceExporter> SOURCE_EXPORTERS =
            Collections.synchronizedMap(new LinkedHashMap<>());

    private static final int[] ALL_HISTORY_TYPES = {};
    private static final int[] USER_HISTORY_TYPES = {
        HistoryReference.TYPE_PROXIED, HistoryReference.TYPE_ZAP_USER
    };

    private final Model model;

    Exporter(Model model) {
        this.model = model;
    }

    static void register(ExporterType exporterType) {
        if (exporterType != null
                && exporterType.getId() != null
                && !exporterType.getId().isBlank()) {
            REGISTERED_TYPES.put(exporterType.getId().toLowerCase(Locale.ROOT), exporterType);
        }
    }

    static void unregister(String typeId) {
        if (typeId != null) {
            REGISTERED_TYPES.remove(typeId.toLowerCase(Locale.ROOT));
        }
    }

    static void registerSourceExporter(
            ExporterOptions.Source source, SourceExporter sourceExporter) {
        if (source != null && sourceExporter != null) {
            SOURCE_EXPORTERS.put(source, sourceExporter);
        }
    }

    static void unregisterSourceExporter(ExporterOptions.Source source) {
        if (source != null) {
            SOURCE_EXPORTERS.remove(source);
        }
    }

    /**
     * Gets the exporter type for the given type ID.
     *
     * @param typeId the export type identifier.
     * @return the exporter type, or {@code null} if not found.
     * @since 0.18.0
     */
    public static ExporterType getExporterType(String typeId) {
        return typeId != null ? REGISTERED_TYPES.get(typeId.toLowerCase(Locale.ROOT)) : null;
    }

    /**
     * Returns all available export types (built-in and registered).
     *
     * @return the list of exporter types.
     * @since 0.18.0
     */
    public static List<ExporterType> getAvailableTypes() {
        return new ArrayList<>(REGISTERED_TYPES.values());
    }

    /**
     * Resolves a type string to an exporter type.
     *
     * @param value the type identifier.
     * @return the exporter type, or the default (HAR) if not found.
     * @since 0.18.0
     */
    public static ExporterType fromString(String value) {
        ExporterType type = getExporterType(value);
        return type != null ? type : getExporterType(HarExporter.ID);
    }

    /**
     * Exports the data with the given options.
     *
     * @param options the exporter options.
     * @return the result of the export.
     */
    public ExporterResult export(ExporterOptions options) {
        ExporterResult result = exportImpl(options);
        Stats.incCounter(
                ExtensionExim.STATS_PREFIX + "exporter." + options.getType() + ".count",
                result.getCount());
        return result;
    }

    private ExporterResult exportImpl(ExporterOptions options) {
        ExporterResult result = new ExporterResult();
        Path file = options.getOutputFile();
        if (!isValid(file, result)) {
            return result;
        }

        try (var writer =
                Files.newBufferedWriter(
                        file,
                        StandardCharsets.UTF_8,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING)) {

            ExporterType optionsType = fromString(options.getType());
            if (Source.SITESTREE.equals(options.getSource())) {
                if (!YamlExporter.isYamlExporter(options.getType())) {
                    result.addError(
                            Constant.messages.getString(
                                    "exim.exporter.error.type.sitestree", options.getType()));
                } else {
                    SitesTreeHandler.exportSitesTree(writer, result, options);
                }
            } else if (Source.CLIENTMAP.equals(options.getSource())) {
                if (!YamlExporter.isYamlExporter(options.getType())) {
                    result.addError(
                            Constant.messages.getString(
                                    "exim.exporter.error.type.clientmap", options.getType()));
                } else {
                    SourceExporter sourceExporter = SOURCE_EXPORTERS.get(Source.CLIENTMAP);
                    if (sourceExporter != null) {
                        sourceExporter.export(writer, options);
                        result.incrementCount();
                    } else {
                        result.addError(
                                Constant.messages.getString(
                                        "exim.exporter.error.source.clientmap.unavailable"));
                    }
                }
            } else {
                if (optionsType != null && !optionsType.supportsMessageExport()) {
                    String sourceName =
                            Constant.messages.getString(
                                    "exim.exporter.source." + options.getSource().getId());
                    result.addError(
                            Constant.messages.getString(
                                    "exim.exporter.error.type.messages", sourceName));
                } else {
                    ExporterType exporterType = createExporterType(options);
                    if (exporterType != null) {
                        exportMessagesImpl(writer, result, options);
                    } else {
                        result.addError(
                                Constant.messages.getString(
                                        "exim.exporter.error.type.unavailable", options.getType()));
                    }
                }
            }

        } catch (IOException e) {
            result.addError(
                    Constant.messages.getString("exim.exporter.error.io", e.getLocalizedMessage()),
                    e);
        } catch (DatabaseException e) {
            result.addError(
                    Constant.messages.getString("exim.exporter.error.db", e.getLocalizedMessage()),
                    e);
        }

        return result;
    }

    private void exportMessagesImpl(
            BufferedWriter writer, ExporterResult result, ExporterOptions options)
            throws DatabaseException, IOException {
        List<Integer> historyIds =
                model.getDb()
                        .getTableHistory()
                        .getHistoryIdsOfHistType(
                                model.getSession().getSessionId(), getHistoryTypes(options));

        ExporterType type = createExporterType(options);
        type.begin(writer);
        Context context = options.getContext();
        for (Integer id : historyIds) {
            HistoryReference ref = new HistoryReference(id, true);
            if (context != null && !context.isInContext(ref)) {
                continue;
            }

            result.incrementCount();
            type.write(writer, ref);
        }
        type.end(writer);
    }

    private static boolean isValid(Path file, ExporterResult result) {
        if (Files.exists(file)) {
            if (!Files.isRegularFile(file)) {
                result.addError(
                        Constant.messages.getString("exim.exporter.error.file.notfile", file));
                return false;
            }
            if (!Files.isWritable(file)) {
                result.addError(
                        Constant.messages.getString("exim.exporter.error.file.notwritable", file));
                return false;
            }
            return true;
        }

        Path parent = file.getParent();
        if (Files.notExists(parent)) {
            result.addError(
                    Constant.messages.getString(
                            "exim.exporter.error.file.parent.notexists", parent));
            return false;
        }
        if (!Files.isDirectory(parent)) {
            result.addError(
                    Constant.messages.getString("exim.exporter.error.file.parent.notdir", parent));
            return false;
        }
        if (!Files.isWritable(parent)) {
            result.addError(
                    Constant.messages.getString(
                            "exim.exporter.error.file.parent.notwritable", parent));
            return false;
        }
        return true;
    }

    private ExporterType createExporterType(ExporterOptions options) {
        String typeId = options.getType();
        if (typeId == null) {
            return getExporterType(HarExporter.ID).createForExport();
        }
        ExporterType type = getExporterType(typeId);
        if (type == null || !type.supportsMessageExport()) {
            return null;
        }
        return type.createForExport();
    }

    private static int[] getHistoryTypes(ExporterOptions options) {
        switch (options.getSource()) {
            case ALL:
                return ALL_HISTORY_TYPES;

            case HISTORY:
            default:
                return USER_HISTORY_TYPES;
        }
    }
}
