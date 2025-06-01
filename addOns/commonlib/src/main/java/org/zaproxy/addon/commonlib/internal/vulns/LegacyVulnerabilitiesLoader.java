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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.ConversionException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.utils.LocaleUtils;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Helper class that loads {@code Vulnerability} from a XML file for a given {@code Locale}. */
@SuppressWarnings("removal")
public final class LegacyVulnerabilitiesLoader {

    private static final Logger LOGGER = LogManager.getLogger(LegacyVulnerabilitiesLoader.class);

    private static final String FILE_NAME_PREFIX = "vulnerabilities";
    private static final String FILE_NAME_EXTENSION = ".xml";

    private LegacyVulnerabilitiesLoader() {}

    /**
     * Returns an unmodifiable {@code List} of {@code Vulnerability} for the given {@code locale}.
     *
     * <p>If there's no perfect match for the given {@code locale} the default will be returned, if
     * available. The list will be empty if an error occurs.
     *
     * @param locale the locale.
     * @return an unmodifiable {@code List} with the {@code Vulnerability} for the given {@code
     *     locale}.
     */
    public static List<org.zaproxy.zap.model.Vulnerability> load(Locale locale) {
        return load(locale, LegacyVulnerabilitiesLoader.class::getResourceAsStream);
    }

    static List<org.zaproxy.zap.model.Vulnerability> load(
            Locale locale, Function<String, InputStream> isProvider) {
        String extension = FILE_NAME_EXTENSION.substring(1);
        var vulnerabilities =
                LocaleUtils.findResource(
                        FILE_NAME_PREFIX,
                        extension,
                        locale,
                        candidateFilename -> {
                            try (var is = isProvider.apply(candidateFilename)) {
                                if (is == null) {
                                    return null;
                                }

                                LOGGER.debug(
                                        "Loading vulnerabilities from {} for locale {}.",
                                        candidateFilename,
                                        locale);
                                var list = loadVulnerabilities(new BufferedInputStream(is));
                                if (list.isEmpty()) {
                                    return null;
                                }
                                return Collections.unmodifiableList(list);
                            } catch (IOException e) {
                                LOGGER.error(e.getMessage(), e);
                                return null;
                            }
                        });

        if (vulnerabilities != null) {
            return vulnerabilities;
        }
        return List.of();
    }

    static List<org.zaproxy.zap.model.Vulnerability> loadVulnerabilities(InputStream is) {
        ZapXmlConfiguration config;
        try {
            config = new ZapXmlConfiguration(is);
        } catch (ConfigurationException e) {
            LOGGER.error(e.getMessage(), e);
            return List.of();
        }

        String[] test;
        try {
            test = config.getStringArray("vuln_items");
        } catch (ConversionException e) {
            LOGGER.error(e.getMessage(), e);
            return List.of();
        }

        List<org.zaproxy.zap.model.Vulnerability> vulns = new ArrayList<>(test.length);

        String name;
        List<String> references;

        for (String item : test) {
            name = "vuln_item_" + item;
            try {
                references =
                        new ArrayList<>(Arrays.asList(config.getStringArray(name + ".reference")));
            } catch (ConversionException e) {
                LOGGER.error(e.getMessage(), e);
                references = new ArrayList<>(0);
            }

            var vuln =
                    new org.zaproxy.zap.model.Vulnerability(
                            item,
                            config.getString(name + ".alert"),
                            config.getString(name + ".desc"),
                            config.getString(name + ".solution"),
                            references);
            vulns.add(vuln);
        }

        return vulns;
    }
}
