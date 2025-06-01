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

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;
import org.zaproxy.addon.exim.har.HarImporterType;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

/**
 * Importer of data (e.g. HAR, URLs).
 *
 * @since 0.13.0
 * @see ExtensionExim#getImporter()
 */
public class Importer {

    private static final Exception STOP_IMPORT_EXCEPTION =
            new Exception() {
                private static final long serialVersionUID = 1L;

                @Override
                public synchronized Throwable fillInStackTrace() {
                    return this;
                }
            };

    Importer() {}

    /**
     * Imports the data with the given options.
     *
     * @param options the importer options.
     * @return the result of the import.
     */
    public ImporterResult apply(ImporterOptions options) {
        ImporterResult result = importImpl(options);
        Stats.incCounter(
                ExtensionExim.STATS_PREFIX + "importer." + options.getType().getId() + ".count",
                result.getCount());
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
            MessageHandler messageHandler = options.getMessageHandler();
            type.begin(reader);
            Context context = options.getContext();

            type.read(
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
            type.end(reader);
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
        switch (options.getType()) {
            case HAR:
            default:
                return new HarImporterType();
        }
    }

    /** An importer type, knows how to import an {@code HttpMessage} from specific data. */
    public interface ImporterType {

        /**
         * Called when the import begins.
         *
         * @param reader from where to import the data.
         * @throws IOException if an error occurs while beginning the import.
         */
        void begin(Reader reader) throws IOException;

        /**
         * Called while importing.
         *
         * @param reader from where to import the data
         * @param handler the message handler.
         * @throws Exception if an error occurs while importing the {@code HttpMessage}.
         */
        void read(Reader reader, MessageHandler handler) throws Exception;

        /**
         * Called when the import ends.
         *
         * @param reader from where to import the data.
         * @throws IOException if an error occurs while ending the import.
         */
        void end(Reader reader) throws IOException;
    }
}
