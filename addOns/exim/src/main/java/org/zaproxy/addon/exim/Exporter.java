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
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.exim.ExporterOptions.Source;
import org.zaproxy.addon.exim.ExporterOptions.Type;
import org.zaproxy.addon.exim.har.HarExporter;
import org.zaproxy.addon.exim.sites.SitesTreeHandler;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

/**
 * Exporter of data (e.g. HAR, URLs).
 *
 * @since 0.13.0
 * @see ExtensionExim#getExporter()
 */
public class Exporter {

    private static final int[] ALL_HISTORY_TYPES = {};
    private static final int[] USER_HISTORY_TYPES = {
        HistoryReference.TYPE_PROXIED, HistoryReference.TYPE_ZAP_USER
    };

    private final Model model;

    Exporter(Model model) {
        this.model = model;
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
                ExtensionExim.STATS_PREFIX + "exporter." + options.getType().getId() + ".count",
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

            if (Source.SITESTREE.equals(options.getSource())) {
                if (!Type.YAML.equals(options.getType())) {
                    result.addError(
                            Constant.messages.getString(
                                    "exim.exporter.error.type.sitestree", options.getType()));
                } else {
                    SitesTreeHandler.exportSitesTree(writer, result);
                }
            } else {
                if (Type.YAML.equals(options.getType())) {
                    result.addError(
                            Constant.messages.getString(
                                    "exim.exporter.error.type.messages", options.getSource()));
                } else {
                    exportMessagesImpl(writer, result, options);
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

    private static ExporterType createExporterType(ExporterOptions options) {
        switch (options.getType()) {
            case URL:
                return UrlExporter.INSTANCE;

            case HAR:
            default:
                return new HarExporter();
        }
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

    /** An exporter type, knows how to export a {@code HistoryReference} to specific data. */
    public interface ExporterType {

        /**
         * Called when the export begins.
         *
         * @param writer to where to export the data.
         * @throws IOException if an error occurs while beginning the export.
         */
        void begin(Writer writer) throws IOException;

        /**
         * Called when the export begins.
         *
         * @param writer to where to export to. the data
         * @param ref the {@code HistoryReference} being exported.
         * @throws IOException if an error occurs while exporting the given {@code
         *     HistoryReference}.
         */
        void write(Writer writer, HistoryReference ref) throws IOException;

        /**
         * Called when the export ends.
         *
         * @param writer to where to export to the data.
         * @throws IOException if an error occurs while ending the export.
         */
        void end(Writer writer) throws IOException;
    }

    private static class UrlExporter implements ExporterType {

        static final UrlExporter INSTANCE = new UrlExporter();

        @Override
        public void begin(Writer writer) {
            // Nothing to do.
        }

        @Override
        public void write(Writer writer, HistoryReference ref) throws IOException {
            writer.write(ref.getURI().getRawURI());
            writer.write('\n');
        }

        @Override
        public void end(Writer writer) {
            // Nothing to do.
        }
    }
}
