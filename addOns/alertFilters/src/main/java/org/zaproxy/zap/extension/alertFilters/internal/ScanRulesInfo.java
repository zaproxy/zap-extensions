/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters.internal;

import java.lang.reflect.Constructor;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ScanRulesInfo extends AbstractList<ScanRulesInfo.Entry> {

    private static final Logger LOGGER = LogManager.getLogger(ScanRulesInfo.class);

    private List<Entry> entries;
    private Map<String, Entry> entriesById;

    public ScanRulesInfo(
            ExtensionActiveScan extensionActiveScan, ExtensionPassiveScan extensionPassiveScan) {
        entries = new ArrayList<>();
        entriesById = new HashMap<>();
        ScanPolicy sp = extensionActiveScan.getPolicyManager().getDefaultScanPolicy();
        for (Plugin scanRule : sp.getPluginFactory().getAllPlugin()) {
            addEntry(scanRule, scanRule.getId(), scanRule.getName());
        }
        if (extensionPassiveScan != null) {
            for (PluginPassiveScanner scanRule : extensionPassiveScan.getPluginPassiveScanners()) {
                addEntry(scanRule, scanRule.getPluginId(), scanRule.getName());
            }
        }
        Collections.sort(entries);
    }

    private void addEntry(Object scanRule, int id, String name) {
        if (id == -1) {
            return;
        }

        String idStr = String.valueOf(id);
        addEntry(idStr, name);

        addAlertRefs(idStr, scanRule);
    }

    private void addAlertRefs(String id, Object scanRule) {
        if (!(scanRule instanceof ExampleAlertProvider)) {
            return;
        }

        ExampleAlertProvider exampleAlertProvider = (ExampleAlertProvider) scanRule;
        if (scanRule instanceof PluginPassiveScanner) {
            try {
                PluginPassiveScanner pps = ((PluginPassiveScanner) exampleAlertProvider).copy();
                Constructor<PassiveScanData> constructor =
                        PassiveScanData.class.getDeclaredConstructor(HttpMessage.class);
                constructor.setAccessible(true);
                PassiveScanData psd =
                        constructor.newInstance(
                                new HttpMessage(new HttpRequestHeader("GET / HTTP/1.1")));
                pps.setHelper(psd);
                exampleAlertProvider = pps;
            } catch (Exception e) {
                LOGGER.warn("Failed to initialize the passive scan rule:", e);
                return;
            }
        }

        List<Alert> exampleAlerts;
        try {
            exampleAlerts = exampleAlertProvider.getExampleAlerts();
        } catch (Exception e) {
            LOGGER.warn("Failed to get the example alerts:", e);
            return;
        }

        if (exampleAlerts == null || exampleAlerts.isEmpty()) {
            return;
        }
        exampleAlerts.stream()
                .filter(e -> !e.getAlertRef().equals(id))
                .forEach(e -> addEntry(e.getAlertRef(), e.getName()));
    }

    private void addEntry(String id, String name) {
        Entry entry = new Entry(id, name);
        entriesById.put(id, entry);
        entries.add(entry);
    }

    public Set<String> getIds() {
        return entriesById.keySet();
    }

    public Entry getById(String id) {
        return entriesById.get(id);
    }

    public String getNameById(String id) {
        Entry entry = entriesById.get(id);
        if (entry != null) {
            return entry.getName();
        }
        return id;
    }

    @Override
    public Entry get(int index) {
        return entries.get(index);
    }

    @Override
    public int size() {
        return entries.size();
    }

    @Override
    public int hashCode() {
        return entries.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return entries.equals(o);
    }

    public static class Entry implements Comparable<Entry> {

        private final String id;
        private final String name;

        Entry(String id, String name) {
            this.id = id;
            this.name = name == null || name.isEmpty() ? id : name + " (" + id + ")";
        }

        public String getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        @Override
        public int compareTo(Entry o) {
            if (o == null) {
                return 1;
            }
            int result = name.compareTo(o.name);
            if (result != 0) {
                return result;
            }
            return id.compareTo(o.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Entry)) {
                return false;
            }
            Entry other = (Entry) obj;
            return Objects.equals(id, other.id);
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
