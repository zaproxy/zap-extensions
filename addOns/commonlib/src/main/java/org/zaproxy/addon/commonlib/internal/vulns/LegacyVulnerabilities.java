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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

/** Loads and provides {@code Vulnerability} using (legacy) core classes. */
@SuppressWarnings({"deprecation", "removal"})
public class LegacyVulnerabilities {

    private static final Logger LOGGER = LogManager.getLogger(LegacyVulnerabilities.class);

    private static Map<String, org.zaproxy.zap.model.Vulnerability> vulnerabilitiesMap;
    private static List<org.zaproxy.zap.model.Vulnerability> vulnerabilities;

    public static void load() {
        try {
            InvocationHandler invocationHandler =
                    (o, method, args) -> {
                        switch (method.getName()) {
                            case "getAll":
                                return getVulnerabilities();

                            case "get":
                                var value = getVulnerabilitiesMap().get(args[0]);
                                return value;

                            default:
                                return null;
                        }
                    };

            setVulnerabilitiesProvider(
                    (org.zaproxy.zap.model.Vulnerabilities.Provider)
                            Proxy.newProxyInstance(
                                    LegacyVulnerabilities.class.getClassLoader(),
                                    new Class<?>[] {
                                        org.zaproxy.zap.model.Vulnerabilities.Provider.class
                                    },
                                    invocationHandler));
        } catch (Exception e) {
            LOGGER.error("Failed to load add-on vulnerabilities:", e);
        }
    }

    public static void unload() {
        setVulnerabilitiesProvider(null);
    }

    private static List<org.zaproxy.zap.model.Vulnerability> getVulnerabilities() {
        if (vulnerabilities == null) {
            vulnerabilities = LegacyVulnerabilitiesLoader.load(Constant.getLocale());
        }
        return vulnerabilities;
    }

    private static Map<String, org.zaproxy.zap.model.Vulnerability> getVulnerabilitiesMap() {
        if (vulnerabilitiesMap == null) {
            Method getId;
            try {
                getId = org.zaproxy.zap.model.Vulnerability.class.getDeclaredMethod("getId");
                getId.setAccessible(true);

                Map<String, org.zaproxy.zap.model.Vulnerability> map = new HashMap<>();
                for (org.zaproxy.zap.model.Vulnerability vuln : getVulnerabilities()) {
                    map.put((String) getId.invoke(vuln), vuln);
                }

                vulnerabilitiesMap = Collections.unmodifiableMap(map);
            } catch (Exception e) {
                LOGGER.error("Failed to get/use core method:", e);
                vulnerabilitiesMap = Map.of();
            }
        }
        return vulnerabilitiesMap;
    }

    private static void setVulnerabilitiesProvider(
            org.zaproxy.zap.model.Vulnerabilities.Provider provider) {
        org.zaproxy.zap.model.Vulnerabilities.setProvider(provider);
    }
}
