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
import java.util.Locale;
import java.util.Objects;
import org.parosproxy.paros.model.HistoryReference;

/**
 * An exporter type that knows how to export a {@code HistoryReference} to specific data.
 *
 * @since 0.18.0
 */
public abstract class ExporterType {

    private final String id;
    private final String name;

    protected ExporterType(String id, String name) {
        this.id = Objects.requireNonNull(id).toLowerCase(Locale.ROOT);
        this.name = Objects.requireNonNull(name);
    }

    /** Returns the type identifier (e.g. "har", "url"). */
    public String getId() {
        return id;
    }

    /** Returns the display name for the UI. */
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExporterType that = (ExporterType) o;
        return hasId(that.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    public boolean hasId(String id) {
        return this.id.equalsIgnoreCase(id);
    }

    /**
     * Called when the export begins.
     *
     * @param writer to where to export the data.
     * @throws IOException if an error occurs while beginning the export.
     */
    public abstract void begin(Writer writer) throws IOException;

    /**
     * Called for each {@code HistoryReference} to export.
     *
     * @param writer to where to export the data.
     * @param ref the {@code HistoryReference} being exported.
     * @throws IOException if an error occurs while exporting.
     */
    public abstract void write(Writer writer, HistoryReference ref) throws IOException;

    /**
     * Called when the export ends.
     *
     * @param writer to where to export the data.
     * @throws IOException if an error occurs while ending the export.
     */
    public abstract void end(Writer writer) throws IOException;

    /**
     * Returns whether this type supports exporting messages (vs. only Sites Tree).
     *
     * @return {@code true} if messages can be exported, {@code false} otherwise.
     */
    public boolean supportsMessageExport() {
        return true;
    }

    /**
     * Creates a new instance for export. Override for stateful types that need a fresh instance per
     * export.
     *
     * @return a new instance for use in export, or {@code this} if stateless.
     */
    public ExporterType createForExport() {
        return this;
    }
}
