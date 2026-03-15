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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
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
    public static final class Type {

        /** The messages are exported as an HAR. */
        public static final Type HAR =
                new Type("har", Constant.messages.getString("exim.exporter.type.har"));

        /** The messages are exported as URLs. */
        public static final Type URL =
                new Type("url", Constant.messages.getString("exim.exporter.type.url"));

        /** The SiteTree will be exported as YAML. */
        public static final Type YAML =
                new Type("yaml", Constant.messages.getString("exim.exporter.type.yaml"));

        private final String id;
        private final String name;

        private Type(String id, String name) {
            this.id = id;
            this.name = name;
        }

        @JsonValue
        public String getId() {
            return id;
        }

        @Override
        public String toString() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Type type = (Type) o;
            return id.equals(type.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }

        @JsonCreator
        public static Type fromString(String value) {
            if (value == null || value.isBlank()) {
                return HAR;
            }
            String lower = value.toLowerCase(Locale.ROOT);
            if (HAR.id.equals(lower)) {
                return HAR;
            }
            if (URL.id.equals(lower)) {
                return URL;
            }
            if (YAML.id.equals(lower)) {
                return YAML;
            }
            String displayName = ExporterTypeRegistry.getDisplayName(value);
            if (displayName != null) {
                return new Type(lower, displayName);
            }
            return HAR;
        }

        /** Returns all available export types (built-in and registered). */
        public static List<Type> getAvailableTypes() {
            List<Type> list = new ArrayList<>();
            list.add(HAR);
            list.add(URL);
            list.add(YAML);
            for (ExporterTypeRegistry.ExporterTypeInfo info :
                    ExporterTypeRegistry.getRegisteredTypes()) {
                list.add(new Type(info.id(), info.displayName()));
            }
            return list;
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
