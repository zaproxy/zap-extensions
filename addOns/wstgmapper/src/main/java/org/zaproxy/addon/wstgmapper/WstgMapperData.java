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
package org.zaproxy.addon.wstgmapper;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.wstgmapper.model.WstgCategory;
import org.zaproxy.addon.wstgmapper.model.WstgTest;

/**
 * Loads the bundled WSTG catalogue and exposes quick lookup helpers for the rest of the add-on.
 *
 * <p>By parsing the JSON once and building an index up front, this class keeps UI and reporting
 * code simple and avoids repeatedly walking the full category structure.
 */
public class WstgMapperData {

    private static final Logger LOGGER = LogManager.getLogger(WstgMapperData.class);

    private static final String WSTG_TESTS_PATH =
            "/org/zaproxy/addon/wstgmapper/resources/data/checklist.json";

    private final List<WstgCategory> categories;

    /** Flat map of WSTG test ID → WstgTest for fast lookup. */
    private final Map<String, WstgTest> testById;

    public WstgMapperData() throws IOException {
        try (InputStream is = WstgMapperData.class.getResourceAsStream(WSTG_TESTS_PATH)) {
            if (is == null) {
                throw new IOException("WSTG tests resource not found: " + WSTG_TESTS_PATH);
            }
            ObjectMapper mapper = new ObjectMapper();
            WstgTestsRoot root = mapper.readValue(is, WstgTestsRoot.class);
            List<WstgCategory> loadedCategories = root.getCategories();
            this.categories =
                    Collections.unmodifiableList(
                            loadedCategories != null ? loadedCategories : List.of());
        }

        Map<String, WstgTest> index = new LinkedHashMap<>();
        for (WstgCategory cat : categories) {
            if (cat.getTests() != null) {
                for (WstgTest test : cat.getTests()) {
                    index.put(test.getId(), test);
                }
            }
        }
        this.testById = Collections.unmodifiableMap(index);
        LOGGER.debug(
                "Loaded {} WSTG tests across {} categories.", testById.size(), categories.size());
    }

    public WstgMapperData(List<WstgCategory> categories) {
        this.categories =
                Collections.unmodifiableList(
                        categories != null ? new ArrayList<>(categories) : List.of());

        Map<String, WstgTest> index = new LinkedHashMap<>();
        for (WstgCategory category : this.categories) {
            if (category.getTests() == null) {
                continue;
            }
            for (WstgTest test : category.getTests()) {
                index.put(test.getId(), test);
            }
        }
        this.testById = Collections.unmodifiableMap(index);
    }

    public List<WstgCategory> getCategories() {
        return categories;
    }

    public Map<String, WstgTest> getTestById() {
        return testById;
    }

    public List<WstgTest> getAllTests() {
        return List.copyOf(testById.values());
    }

    public WstgTest getTest(String id) {
        return testById.get(id);
    }

    /** Root deserialization helper. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class WstgTestsRoot {

        @JsonDeserialize(using = CategoriesDeserializer.class)
        private List<WstgCategory> categories;

        public List<WstgCategory> getCategories() {
            return categories;
        }

        public void setCategories(List<WstgCategory> categories) {
            this.categories = categories;
        }
    }

    /**
     * Deserializes the {@code "categories"} field from either an array (legacy format) or an object
     * keyed by category name (new format from comp.json).
     */
    @SuppressWarnings("serial")
    static class CategoriesDeserializer extends StdDeserializer<List<WstgCategory>> {

        CategoriesDeserializer() {
            super(List.class);
        }

        @Override
        public List<WstgCategory> deserialize(JsonParser p, DeserializationContext ctx)
                throws IOException {
            JsonNode node = p.getCodec().readTree(p);
            List<WstgCategory> result = new ArrayList<>();
            if (node.isArray()) {
                for (JsonNode catNode : node) {
                    result.add(p.getCodec().treeToValue(catNode, WstgCategory.class));
                }
            } else if (node.isObject()) {
                Iterator<String> fieldNames = node.fieldNames();
                while (fieldNames.hasNext()) {
                    String categoryName = fieldNames.next();
                    JsonNode catData = node.get(categoryName);
                    WstgCategory cat = new WstgCategory();
                    cat.setName(categoryName);
                    cat.setId(catData.path("id").asText(null));
                    JsonNode testsNode = catData.path("tests");
                    if (testsNode.isArray()) {
                        List<WstgTest> tests = new ArrayList<>();
                        for (JsonNode testNode : testsNode) {
                            tests.add(p.getCodec().treeToValue(testNode, WstgTest.class));
                        }
                        cat.setTests(tests);
                    }
                    result.add(cat);
                }
            }
            return result;
        }
    }
}
