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
package org.zaproxy.addon.pscan.internal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.pscan.PassiveScannersManager;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ScanRuleManager implements PassiveScannersManager {

    private static final Logger LOGGER = LogManager.getLogger(ScanRuleManager.class);

    private List<PassiveScanner> scanRules = new CopyOnWriteArrayList<>();
    private Set<String> scannerNames = new HashSet<>();

    public ScanRuleManager() {}

    @Override
    public boolean add(PassiveScanner scanRule) {
        if (scanRule == null) {
            throw new IllegalArgumentException("Parameter must not be null.");
        }

        if (scanRule instanceof PluginPassiveScanner) {
            return addPluginPassiveScannerImpl((PluginPassiveScanner) scanRule);
        }
        return addPassiveScannerImpl(scanRule);
    }

    private boolean addPluginPassiveScannerImpl(PluginPassiveScanner scanner) {
        if (scanner instanceof RegexAutoTagScanner) {
            return false;
        }

        boolean added = addPassiveScannerImpl(scanner);

        if (added) {
            LOGGER.info("Loaded passive scan rule: {}", scanner.getName());
        }
        if (scanner.getPluginId() == -1) {
            LOGGER.error(
                    "The passive scan rule \"{}\" [{}] does not have a defined ID.",
                    scanner.getName(),
                    scanner.getClass().getCanonicalName());
        }

        return added;
    }

    private boolean addPassiveScannerImpl(PassiveScanner passiveScanner) {
        String name = passiveScanner.getName();
        if (scannerNames.contains(name)) {
            LOGGER.error("Duplicate passive scan rule name: {}", passiveScanner.getName());
            return false;
        }
        scannerNames.add(name);
        return scanRules.add(passiveScanner);
    }

    @Override
    public PluginPassiveScanner getScanRule(int id) {
        for (PassiveScanner scanner : scanRules) {
            if (scanner instanceof PluginPassiveScanner) {
                if (((PluginPassiveScanner) scanner).getPluginId() == id) {
                    return (PluginPassiveScanner) scanner;
                }
            }
        }
        return null;
    }

    @Override
    public List<PassiveScanner> getScanners() {
        return scanRules;
    }

    @Override
    public List<PluginPassiveScanner> getScanRules() {
        List<PluginPassiveScanner> pluginPassiveScanners = new ArrayList<>();
        for (PassiveScanner scanner : scanRules) {
            if ((scanner instanceof PluginPassiveScanner)
                    && !(scanner instanceof RegexAutoTagScanner)) {
                pluginPassiveScanners.add((PluginPassiveScanner) scanner);
            }
        }
        return pluginPassiveScanners;
    }

    @Override
    public boolean remove(PassiveScanner scanRule) {
        if (scanRule == null) {
            throw new IllegalArgumentException("Parameter must not be null.");
        }

        return remove(scanRule.getClass().getName());
    }

    public boolean remove(String className) {
        PassiveScanner scanner = getScanRule(className);
        if (scanner != null) {
            scannerNames.remove(scanner.getName());
            return scanRules.remove(scanner);
        }
        return false;
    }

    public void setAutoTagScanners(List<RegexAutoTagScanner> autoTagScanners) {
        List<PassiveScanner> tempScanners =
                new ArrayList<>(scanRules.size() + autoTagScanners.size());

        for (PassiveScanner scanner : scanRules) {
            if (scanner instanceof RegexAutoTagScanner) {
                this.scannerNames.remove(scanner.getName());
            } else {
                tempScanners.add(scanner);
            }
        }

        for (PassiveScanner scanner : autoTagScanners) {
            if (scannerNames.contains(scanner.getName())) {
                LOGGER.error("Duplicate passive scan rule name: {}", scanner.getName());
            } else {
                tempScanners.add(scanner);
                scannerNames.add(scanner.getName());
            }
        }

        this.scanRules = new CopyOnWriteArrayList<>(tempScanners);
    }

    public PassiveScanner getScanRule(String className) {
        for (PassiveScanner scanner : scanRules) {
            if (scanner.getClass().getName().equals(className)) {
                return scanner;
            }
        }
        return null;
    }
}
