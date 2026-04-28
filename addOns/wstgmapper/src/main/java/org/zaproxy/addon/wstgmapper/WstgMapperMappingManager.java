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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Loads the mapping data that links ZAP findings and detected technologies back to WSTG tests.
 *
 * <p>The alert consumer and the technology filter both rely on this class so that mapping logic is
 * defined once in the bundled JSON instead of being scattered throughout the add-on.
 */
public class WstgMapperMappingManager {

    private static final Logger LOGGER = LogManager.getLogger(WstgMapperMappingManager.class);

    private static final String MAPPINGS_PATH =
            "/org/zaproxy/addon/wstgmapper/resources/data/mappings.json";

    /** ZAP plugin ID → set of WSTG test IDs. */
    private final Map<Integer, Set<String>> pluginMappings;

    /** Technology name (lower-case) → set of WSTG test IDs. */
    private final Map<String, Set<String>> technologyMappings;

    public WstgMapperMappingManager() throws IOException {
        try (InputStream is = WstgMapperMappingManager.class.getResourceAsStream(MAPPINGS_PATH)) {
            if (is == null) {
                throw new IOException("WSTG mappings resource not found: " + MAPPINGS_PATH);
            }
            ObjectMapper mapper = new ObjectMapper();
            MappingsRoot root = mapper.readValue(is, MappingsRoot.class);

            Map<Integer, Set<String>> pMap = new HashMap<>();
            if (root.getPluginMappings() != null) {
                for (PluginEntry entry : root.getPluginMappings()) {
                    pMap.put(entry.getPluginId(), new TreeSet<>(entry.getWstgIds()));
                }
            }
            pluginMappings = Collections.unmodifiableMap(pMap);

            Map<String, Set<String>> tMap = new HashMap<>();
            if (root.getTechnologyMappings() != null) {
                for (TechEntry entry : root.getTechnologyMappings()) {
                    tMap.put(
                            entry.getTechnology().toLowerCase(), new TreeSet<>(entry.getWstgIds()));
                }
            }
            technologyMappings = Collections.unmodifiableMap(tMap);
        }
        LOGGER.debug(
                "Loaded {} plugin mappings and {} technology mappings.",
                pluginMappings.size(),
                technologyMappings.size());
    }

    WstgMapperMappingManager(
            Map<Integer, Set<String>> pluginMappings, Map<String, Set<String>> technologyMappings) {
        Map<Integer, Set<String>> normalizedPlugins = new HashMap<>();
        if (pluginMappings != null) {
            for (Map.Entry<Integer, Set<String>> entry : pluginMappings.entrySet()) {
                normalizedPlugins.put(
                        entry.getKey(),
                        Collections.unmodifiableSet(new TreeSet<>(entry.getValue())));
            }
        }
        this.pluginMappings = Collections.unmodifiableMap(normalizedPlugins);

        Map<String, Set<String>> normalizedTech = new HashMap<>();
        if (technologyMappings != null) {
            for (Map.Entry<String, Set<String>> entry : technologyMappings.entrySet()) {
                normalizedTech.put(
                        entry.getKey().toLowerCase(),
                        Collections.unmodifiableSet(new TreeSet<>(entry.getValue())));
            }
        }
        this.technologyMappings = Collections.unmodifiableMap(normalizedTech);
    }

    /**
     * Returns the set of WSTG test IDs related to the given ZAP plugin ID, or an empty set if there
     * is no mapping.
     */
    public Set<String> getWstgIdsForPlugin(int pluginId) {
        return pluginMappings.getOrDefault(pluginId, Collections.emptySet());
    }

    /**
     * Returns the set of WSTG test IDs related to the given technology name, or an empty set if
     * there is no mapping.
     */
    public Set<String> getWstgIdsForTechnology(String technology) {
        if (technology == null || technology.isBlank()) {
            return Collections.emptySet();
        }
        return technologyMappings.getOrDefault(technology.toLowerCase(), Collections.emptySet());
    }

    /** Returns the unmodifiable set of all known technology names (lower-case). */
    public Set<String> getAllTechnologies() {
        return Collections.unmodifiableSet(new TreeSet<>(technologyMappings.keySet()));
    }

    public Set<String> getAllMappedWstgIds() {
        Set<String> result = new LinkedHashSet<>();
        for (Set<String> ids : pluginMappings.values()) {
            result.addAll(ids);
        }
        return Collections.unmodifiableSet(result);
    }

    public boolean hasPluginMapping(String testId) {
        if (testId == null || testId.isBlank()) {
            return false;
        }
        return getAllMappedWstgIds().contains(testId);
    }

    // ---- JSON deserialization helpers ----

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class MappingsRoot {
        private List<PluginEntry> pluginMappings;
        private List<TechEntry> technologyMappings;

        public List<PluginEntry> getPluginMappings() {
            return pluginMappings;
        }

        public void setPluginMappings(List<PluginEntry> pluginMappings) {
            this.pluginMappings = pluginMappings;
        }

        public List<TechEntry> getTechnologyMappings() {
            return technologyMappings;
        }

        public void setTechnologyMappings(List<TechEntry> technologyMappings) {
            this.technologyMappings = technologyMappings;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PluginEntry {
        private int pluginId;
        private List<String> wstgIds;

        public int getPluginId() {
            return pluginId;
        }

        public void setPluginId(int pluginId) {
            this.pluginId = pluginId;
        }

        public List<String> getWstgIds() {
            return wstgIds;
        }

        public void setWstgIds(List<String> wstgIds) {
            this.wstgIds = wstgIds;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TechEntry {
        private String technology;
        private List<String> wstgIds;

        public String getTechnology() {
            return technology;
        }

        public void setTechnology(String technology) {
            this.technology = technology;
        }

        public List<String> getWstgIds() {
            return wstgIds;
        }

        public void setWstgIds(List<String> wstgIds) {
            this.wstgIds = wstgIds;
        }
    }
}
