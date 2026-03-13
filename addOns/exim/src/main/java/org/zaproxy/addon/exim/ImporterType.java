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

import java.io.Reader;
import java.util.Locale;
import java.util.Objects;
import org.zaproxy.addon.exim.ImporterOptions.MessageHandler;

/**
 * An importer type that knows how to import an {@code HttpMessage} from specific data.
 *
 * @since 0.18.0
 */
public abstract class ImporterType {

    private final String id;
    private final String name;

    protected ImporterType(String id, String name) {
        this.id = Objects.requireNonNull(id).toLowerCase(Locale.ROOT);
        this.name = Objects.requireNonNull(name);
    }

    /** Returns the type identifier (e.g. "har"). */
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

    public boolean hasId(String id) {
        return this.id.equalsIgnoreCase(id);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ImporterType that = (ImporterType) o;
        return hasId(that.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    /**
     * Imports data from the reader and passes each {@code HttpMessage} to the handler.
     *
     * @param reader from where to import the data.
     * @param handler the message handler to receive imported messages.
     * @throws Exception if an error occurs while importing.
     */
    public abstract void importData(Reader reader, MessageHandler handler) throws Exception;
}
