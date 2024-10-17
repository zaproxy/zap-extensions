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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.nio.file.Path;
import java.util.Locale;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;

/**
 * The options for the exporter.
 *
 * @since 0.13.0
 * @see Exporter
 */
public class ExporterOptions {

    private final Context context;
    private final Type type;
    private final Format format;
    private final Path outputFile;

    private ExporterOptions(Context context, Type type, Format format, Path outputFile) {
        this.context = context;
        this.type = type;
        this.format = format;
        this.outputFile = outputFile;
    }

    public Context getContext() {
        return context;
    }

    public Type getType() {
        return type;
    }

    public Format getFormat() {
        return format;
    }

    public Path getOutputFile() {
        return outputFile;
    }

    /**
     * Returns a new builder.
     *
     * @return the options builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder of options.
     *
     * @see #build()
     */
    public static class Builder {

        private Context context;
        private Type type;
        private Format format;
        private Path outputFile;

        private Builder() {
            type = Type.HAR;
            format = Format.HISTORY;
        }

        /**
         * Sets the context.
         *
         * <p>Default value: {@code null}.
         *
         * @param context the context.
         * @return the builder for chaining.
         */
        public Builder setContext(Context context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the type.
         *
         * <p>Default value: {@link Type#HAR}.
         *
         * @param type the type.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the type is {@code null}.
         */
        public Builder setType(Type type) {
            if (type == null) {
                throw new IllegalArgumentException("The type must not be null.");
            }
            this.type = type;
            return this;
        }

        /**
         * Sets the format.
         *
         * <p>Default value: {@link Format#HISTORY}.
         *
         * @param format the format.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the format is {@code null}.
         */
        public Builder setFormat(Format format) {
            if (format == null) {
                throw new IllegalArgumentException("The format must not be null.");
            }
            this.format = format;
            return this;
        }

        /**
         * Sets the output file.
         *
         * <p>Default value: {@code null}.
         *
         * @param outputFile the output file.
         * @return the builder for chaining.
         */
        public Builder setOutputFile(Path outputFile) {
            this.outputFile = outputFile;
            return this;
        }

        /**
         * Builds the options from the specified data.
         *
         * @return the options with specified data.
         * @throws IllegalStateException if built without {@link #setOutputFile(Path) setting the
         *     output file}.
         */
        public final ExporterOptions build() {
            if (outputFile == null) {
                throw new IllegalStateException("The outputFile must be set.");
            }
            return new ExporterOptions(context, type, format, outputFile);
        }
    }

    /** The type of export. */
    public enum Type {
        /** The messages are exported as an HAR. */
        HAR,
        /** The messages are exported as URLs. */
        URL;

        private String id;
        private String name;

        private Type() {
            id = name().toLowerCase(Locale.ROOT);
            name = Constant.messages.getString("exim.exporter.type." + id);
        }

        @JsonValue
        public String getId() {
            return id;
        }

        @Override
        public String toString() {
            return name;
        }

        @JsonCreator
        public static Type fromString(String value) {
            if (value == null || value.isBlank()) {
                return HAR;
            }

            if (HAR.id.equalsIgnoreCase(value)) {
                return HAR;
            }
            if (URL.id.equalsIgnoreCase(value)) {
                return URL;
            }
            return HAR;
        }
    }

    /** The format of the data. */
    public enum Format {
        /** Exports the messages proxied and manually accessed by the user. */
        HISTORY,
        /** Exports all messages accessed, includes temporary messages. */
        SITES;

        private String id;
        private String name;

        private Format() {
            id = name().toLowerCase(Locale.ROOT);
            name = Constant.messages.getString("exim.exporter.format." + id);
        }

        @JsonValue
        public String getId() {
            return id;
        }

        @Override
        public String toString() {
            return name;
        }

        @JsonCreator
        public static Format fromString(String value) {
            if (value == null || value.isBlank()) {
                return HISTORY;
            }

            if (HISTORY.id.equalsIgnoreCase(value)) {
                return HISTORY;
            }
            if (SITES.id.equalsIgnoreCase(value)) {
                return SITES;
            }
            return HISTORY;
        }
    }
}
