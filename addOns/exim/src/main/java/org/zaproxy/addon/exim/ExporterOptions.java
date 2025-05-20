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
    private final Source source;
    private final Path outputFile;

    private ExporterOptions(Context context, Type type, Source source, Path outputFile) {
        this.context = context;
        this.type = type;
        this.source = source;
        this.outputFile = outputFile;
    }

    public Context getContext() {
        return context;
    }

    public Type getType() {
        return type;
    }

    public Source getSource() {
        return source;
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
        private Source source;
        private Path outputFile;

        private Builder() {
            type = Type.HAR;
            source = Source.HISTORY;
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
         * Sets the source.
         *
         * <p>Default value: {@link Source#HISTORY}.
         *
         * @param source the source.
         * @return the builder for chaining.
         * @throws IllegalArgumentException if the source is {@code null}.
         */
        public Builder setSource(Source source) {
            if (source == null) {
                throw new IllegalArgumentException("The source must not be null.");
            }
            this.source = source;
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
            return new ExporterOptions(context, type, source, outputFile);
        }
    }

    /** The type of export. */
    public enum Type {
        /** The messages are exported as an HAR. */
        HAR,
        /** The messages are exported as URLs. */
        URL,
        /** The SiteTree will be exported as YAML. */
        YAML;

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
            if (YAML.id.equalsIgnoreCase(value)) {
                return YAML;
            }
            return HAR;
        }
    }

    /** The source of the data. */
    public enum Source {
        /** Exports the messages proxied and manually accessed by the user. */
        HISTORY,
        /** Exports all messages accessed, includes temporary messages. */
        ALL,
        /** Exports the Sites tree, only in yaml format */
        SITESTREE;

        private String id;
        private String name;

        private Source() {
            id = name().toLowerCase(Locale.ROOT);
            name = Constant.messages.getString("exim.exporter.source." + id);
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
        public static Source fromString(String value) {
            if (value == null || value.isBlank()) {
                return HISTORY;
            }

            if (HISTORY.id.equalsIgnoreCase(value)) {
                return HISTORY;
            }
            if (ALL.id.equalsIgnoreCase(value)) {
                return ALL;
            }
            if (SITESTREE.id.equalsIgnoreCase(value)) {
                return SITESTREE;
            }
            return HISTORY;
        }
    }
}
