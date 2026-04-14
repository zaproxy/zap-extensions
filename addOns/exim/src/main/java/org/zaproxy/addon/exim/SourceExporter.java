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
package org.zaproxy.addon.exim;

import java.io.IOException;
import java.io.Writer;

/**
 * Exports data from a custom source to a writer.
 *
 * <p>Registered with {@link ExtensionExim#registerSourceExporter(ExporterOptions.Source,
 * SourceExporter)} to handle a specific {@link ExporterOptions.Source} value that is not built in
 * to the Import/Export add-on.
 *
 * @since 0.19.0
 * @see ExtensionExim#registerSourceExporter(ExporterOptions.Source, SourceExporter)
 */
@FunctionalInterface
public interface SourceExporter {

    /**
     * Exports data to the given writer.
     *
     * @param writer to where to export the data.
     * @param options the exporter options (e.g. context for filtering).
     * @throws IOException if an error occurs while exporting.
     */
    void export(Writer writer, ExporterOptions options) throws IOException;
}
