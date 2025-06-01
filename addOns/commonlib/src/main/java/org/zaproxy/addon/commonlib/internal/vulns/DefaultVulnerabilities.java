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
package org.zaproxy.addon.commonlib.internal.vulns;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerabilities;
import org.zaproxy.addon.commonlib.vulnerabilities.Vulnerability;
import org.zaproxy.zap.utils.LocaleUtils;

public class DefaultVulnerabilities implements Vulnerabilities {

    private static final Logger LOGGER = LogManager.getLogger(DefaultVulnerabilities.class);

    private static final String FILE_NAME_PREFIX = "vulnerabilities";
    private static final String FILE_NAME_EXTENSION = ".xml";

    private static Vulnerabilities instance;

    private final List<Vulnerability> list;
    private final Map<String, Vulnerability> map;

    /**
     * Gets the instance.
     *
     * @return the instance, never {@code null}.
     */
    public static Vulnerabilities getInstance() {
        if (instance == null) {
            instance = new DefaultVulnerabilities();
        }
        return instance;
    }

    DefaultVulnerabilities() {
        this(Constant.getLocale());
    }

    DefaultVulnerabilities(Locale locale) {
        var result = loadVulnerabilities(locale);
        list = result.getList();
        map = result.getMap();
    }

    @Override
    public List<Vulnerability> getAll() {
        return list;
    }

    @Override
    public Vulnerability get(String id) {
        return map.get(id);
    }

    private LoadResult loadVulnerabilities(Locale locale) {
        var extension = FILE_NAME_EXTENSION.substring(1);
        var result =
                LocaleUtils.findResource(
                        FILE_NAME_PREFIX,
                        extension,
                        locale,
                        candidateFilename -> {
                            try (var is = getClass().getResourceAsStream(candidateFilename)) {
                                if (is == null) {
                                    return null;
                                }

                                LOGGER.debug(
                                        "Loading vulnerabilities from {} for locale {}.",
                                        candidateFilename,
                                        locale);

                                return loadVulnerabilities(is);
                            } catch (IOException e) {
                                LOGGER.error(e.getMessage(), e);
                                return null;
                            }
                        });

        if (result != null) {
            return result;
        }
        return new LoadResult(new PersistedVulnerabilities());
    }

    static LoadResult loadVulnerabilities(InputStream is) throws IOException {
        var persisted =
                new XmlMapper()
                        .readValue(new BufferedInputStream(is), PersistedVulnerabilities.class);
        return new LoadResult(persisted);
    }

    static class LoadResult {

        private static final int VULN_ITEM_PREFIX_LENGTH = "vuln_item_".length();

        private final List<Vulnerability> list;
        private final Map<String, Vulnerability> map;

        LoadResult(PersistedVulnerabilities persisted) {
            var vulnerabilities = persisted.getVulnerabilities();
            list = vulnerabilities.values().stream().collect(Collectors.toUnmodifiableList());
            map =
                    vulnerabilities.entrySet().stream()
                            .collect(
                                    Collectors.toUnmodifiableMap(
                                            e -> trimKeyPrefix(e),
                                            e -> {
                                                DefaultVulnerability value = e.getValue();
                                                value.setId(trimKeyPrefix(e));
                                                return value;
                                            }));
        }

        private static String trimKeyPrefix(Entry<String, DefaultVulnerability> e) {
            return e.getKey().substring(VULN_ITEM_PREFIX_LENGTH);
        }

        public List<Vulnerability> getList() {
            return list;
        }

        public Map<String, Vulnerability> getMap() {
            return map;
        }
    }

    @JsonIgnoreProperties("vuln_items")
    private static class PersistedVulnerabilities {

        @JsonAnySetter
        private Map<String, DefaultVulnerability> vulnerabilities = new LinkedHashMap<>();

        public Map<String, DefaultVulnerability> getVulnerabilities() {
            return vulnerabilities;
        }
    }
}
