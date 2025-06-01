/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.retire.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.util.StdConverter;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@JsonIgnoreProperties("filecontentreplace")
public class Extractors {

    public static final String TYPE_FUNC = "func";
    public static final String TYPE_URI = "uri";
    public static final String TYPE_FILENAME = "filename";
    public static final String TYPE_FILECONTENT = "filecontent";
    public static final String TYPE_HASHES = "hashes";

    @JsonDeserialize(contentConverter = VersionConverter.class)
    private List<String> func = null;

    @JsonDeserialize(contentConverter = VersionConverter.class)
    private List<String> filename = null;

    @JsonDeserialize(contentConverter = VersionConverter.class)
    private List<String> uri = null;

    @JsonDeserialize(contentConverter = VersionConverter.class)
    private List<String> filecontent = null;

    private Map<String, String> hashes; // hash, version

    public List<String> getFunc() {
        return func;
    }

    public void setFunc(List<String> func) {
        this.func = func;
    }

    public List<String> getFilename() {
        return filename;
    }

    public void setFilename(List<String> filename) {
        this.filename = filename;
    }

    public List<String> getUri() {
        return uri;
    }

    public void setUri(List<String> uri) {
        this.uri = uri;
    }

    public List<String> getFilecontent() {
        return filecontent;
    }

    public void setFilecontent(List<String> filecontent) {
        this.filecontent = filecontent;
    }

    public Map<String, String> getHashes() {
        if (hashes == null) {
            return Collections.emptyMap();
        }
        return hashes;
    }

    public void setHashes(Map<String, String> hashes) {
        this.hashes = hashes;
    }

    public List<String> get(String type) {
        switch (type) {
            case TYPE_FUNC:
                return getFunc();
            case TYPE_URI:
                return getUri();
            case TYPE_FILENAME:
                return getFilename();
            case TYPE_FILECONTENT:
                return getFilecontent();
            default:
                return getUri();
        }
    }

    static class VersionConverter extends StdConverter<String, String> {

        private static final String VERSION_TOKEN = "§§version§§";
        private static final String VERSION_SUB_PATTERN = "[0-9][0-9a-z._\\-]+?";

        @Override
        public String convert(String value) {
            return fixPattern(value);
        }

        static String fixPattern(String inPattern) {
            String goodPattern = inPattern.replace(VERSION_TOKEN, VERSION_SUB_PATTERN);
            if (goodPattern.contains("{")) {
                // PatternSyntaxException: {} is treated as an empty number of chars definition ex:
                // [a-z]{8}
                goodPattern = goodPattern.replaceAll("\\{\\}", "\\\\{\\\\}");
            }
            if (goodPattern.endsWith(VERSION_SUB_PATTERN + ")")) {
                // If the pattern ends with a version sub pattern, then artificially bound it with a
                // whitespace check
                goodPattern = goodPattern + "\\s";
            }
            return goodPattern;
        }
    }
}
