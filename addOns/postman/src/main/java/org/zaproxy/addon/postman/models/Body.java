/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman.models;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.List;
import org.zaproxy.addon.postman.deserializers.ListDeserializer;
import org.zaproxy.addon.postman.deserializers.ObjectDeserializer;

/** Represents the body of a request in the Postman format. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Body {

    public static final String RAW = "raw";
    public static final String URL_ENCODED = "urlencoded";
    public static final String FORM_DATA = "formdata";
    public static final String FILE = "file";
    public static final String GRAPHQL = "graphql";

    private static final List<String> ALLOWED_MODES =
            List.of(RAW, URL_ENCODED, FORM_DATA, FILE, GRAPHQL);

    @JsonDeserialize(using = ObjectDeserializer.class)
    private String mode;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private String raw;

    @JsonDeserialize(using = ListDeserializer.class)
    private List<KeyValueData> urlencoded;

    @JsonDeserialize(using = ListDeserializer.class)
    @JsonProperty("formdata")
    private List<KeyValueData> formData;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private File file;

    @JsonDeserialize(using = ObjectDeserializer.class)
    @JsonProperty("graphql")
    private GraphQl graphQl;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private Options options;

    @JsonDeserialize(using = ObjectDeserializer.class)
    private boolean disabled;

    public Body() {}

    public Body(String mode) {
        this.mode = mode;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        if (ALLOWED_MODES.contains(mode)) {
            this.mode = mode;
        }
    }

    public String getRaw() {
        return raw;
    }

    public void setRaw(String raw) {
        this.raw = raw;
    }

    public List<KeyValueData> getUrlencoded() {
        return urlencoded;
    }

    public void setUrlencoded(List<KeyValueData> urlencoded) {
        this.urlencoded = urlencoded;
    }

    public List<KeyValueData> getFormData() {
        return formData;
    }

    public void setFormData(List<KeyValueData> formData) {
        this.formData = formData;
    }

    public File getFile() {
        return file;
    }

    public void setFile(File file) {
        this.file = file;
    }

    public GraphQl getGraphQl() {
        return graphQl;
    }

    public void setGraphQl(GraphQl graphQl) {
        this.graphQl = graphQl;
    }

    public Options getOptions() {
        return options;
    }

    public void setOptions(Options options) {
        this.options = options;
    }

    public boolean isDisabled() {
        return disabled;
    }

    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class File {
        @JsonSetter(nulls = Nulls.SKIP)
        @JsonDeserialize(using = ObjectDeserializer.class)
        private String src = "";

        public String getSrc() {
            return src;
        }

        public void setSrc(String src) {
            this.src = src;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class GraphQl {
        @JsonSetter(nulls = Nulls.SKIP)
        @JsonDeserialize(using = ObjectDeserializer.class)
        private String query = "";

        @JsonDeserialize(using = ObjectDeserializer.class)
        private String variables;

        public String getQuery() {
            return query;
        }

        public void setQuery(String query) {
            this.query = query;
        }

        public String getVariables() {
            return variables;
        }

        public void setVariables(String variables) {
            this.variables = variables;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Options {
        @JsonDeserialize(using = ObjectDeserializer.class)
        private RawOption raw;

        public RawOption getRaw() {
            return raw;
        }

        public void setRaw(RawOption raw) {
            this.raw = raw;
        }

        public static class RawOption {
            @JsonDeserialize(using = ObjectDeserializer.class)
            private String language;

            public String getLanguage() {
                return language;
            }

            public void setLanguage(String language) {
                this.language = language;
            }
        }
    }
}
