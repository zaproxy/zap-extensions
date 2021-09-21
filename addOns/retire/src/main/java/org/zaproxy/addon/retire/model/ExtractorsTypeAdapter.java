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

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ExtractorsTypeAdapter extends TypeAdapter<Extractors> {

    private static final String VERSION_TOKEN = "§§version§§";
    private static final String VERSION_SUB_PATTERN = "[0-9][0-9a-z._\\-]+?";

    @Override
    public Extractors read(JsonReader in) throws IOException {
        Extractors extractors = new Extractors();

        in.beginObject();
        while (in.hasNext()) {
            switch (in.nextName()) {
                case Extractors.TYPE_FUNC:
                    in.beginArray();
                    List<String> funcs = new ArrayList<>();
                    while (in.hasNext()) {
                        String aFunc = in.nextString();
                        aFunc = fixPattern(aFunc);
                        funcs.add(aFunc);
                    }
                    extractors.setFunc(funcs);
                    in.endArray();
                    break;
                case Extractors.TYPE_FILENAME:
                    in.beginArray();
                    List<String> filenames = new ArrayList<>();
                    while (in.hasNext()) {
                        String aFilename = in.nextString();
                        aFilename = fixPattern(aFilename);
                        filenames.add(aFilename);
                    }
                    extractors.setFilename(filenames);
                    in.endArray();
                    break;
                case Extractors.TYPE_FILECONTENT:
                    in.beginArray();
                    List<String> filecontents = new ArrayList<>();
                    while (in.hasNext()) {
                        String aFilecontent = in.nextString();
                        aFilecontent = fixPattern(aFilecontent);
                        filecontents.add(aFilecontent);
                    }
                    extractors.setFilecontent(filecontents);
                    in.endArray();
                    break;
                case Extractors.TYPE_URI:
                    in.beginArray();
                    List<String> uris = new ArrayList<>();
                    while (in.hasNext()) {
                        String aUri = in.nextString();
                        aUri = fixPattern(aUri);
                        uris.add(aUri);
                    }
                    extractors.setUri(uris);
                    in.endArray();
                    break;
                case Extractors.TYPE_HASHES:
                    in.beginObject();
                    Map<String, String> hashes = new HashMap<>();
                    while (in.hasNext()) {
                        String key = in.nextName();
                        String value = in.nextString();
                        hashes.put(key, value);
                    }
                    extractors.setHashes(hashes);
                    in.endObject();
                    break;
                case "filecontentreplace":
                    in.beginArray();
                    while (in.hasNext()) {
                        @SuppressWarnings("unused")
                        String ignore = in.nextString(); // Ignore
                    }
                    in.endArray();
                    break;
            }
        }
        in.endObject();

        return extractors;
    }

    static String fixPattern(String inPattern) {
        String goodPattern;
        goodPattern = inPattern.replace(VERSION_TOKEN, VERSION_SUB_PATTERN);
        if (goodPattern.contains("{")) {
            goodPattern =
                    goodPattern.replaceAll(
                            "\\{\\}", "\\\\{\\\\}"); // PatternSyntaxException: {} is treated
            // as an empty number of chars definition ex: [a-z]{8}
        }
        if (goodPattern.endsWith(VERSION_SUB_PATTERN + ")")) {
            // If the pattern ends with a version sub pattern, then artificially bound it with a
            // whitespace check
            goodPattern = goodPattern + "\\s";
        }
        return goodPattern;
    }

    @Override
    public void write(JsonWriter out, Extractors value) throws IOException {
        // Nothing to do
    }
}
