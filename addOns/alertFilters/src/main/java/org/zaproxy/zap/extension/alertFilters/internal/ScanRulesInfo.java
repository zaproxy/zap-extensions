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

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.ascan.ScanPolicy;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class ScanRulesInfo extends AbstractList<ScanRulesInfo.Entry> {

    private List<Entry> entries;
    private Map<Integer, Entry> entriesById;

    public ScanRulesInfo(
            ExtensionActiveScan extensionActiveScan,
            List<PluginPassiveScanner> builtInPassiveScanRules,
            List<PluginPassiveScanner> passiveScanRules) {
        entries = new ArrayList<>();
        entriesById = new HashMap<>();
        ScanPolicy sp = extensionActiveScan.getPolicyManager().getDefaultScanPolicy();
        for (Plugin scanRule : sp.getPluginFactory().getAllPlugin()) {
            addEntry(scanRule.getId(), scanRule.getName());
        }
        for (PluginPassiveScanner scanRule : builtInPassiveScanRules) {
            addEntry(scanRule.getPluginId(), scanRule.getName());
        }
        for (PluginPassiveScanner scanRule : passiveScanRules) {
            addEntry(scanRule.getPluginId(), scanRule.getName());
        }
        Collections.sort(entries);
    }

    private void addEntry(int id, String name) {
        if (id == -1) {
            return;
        }

        Entry entry = new Entry(id, name);
        entriesById.put(id, entry);
        entries.add(entry);
    }

    public Entry getById(int id) {
        return entriesById.get(id);
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

        private final int id;
        private final String name;

        Entry(int id, String name) {
            this.id = id;
            this.name =
                    name == null || name.isEmpty() ? String.valueOf(id) : name + " (" + id + ")";
        }

        public int getId() {
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
            return Integer.compare(id, o.id);
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
            return id == other.id;
        }

        @Override
        public String toString() {
            return name;
        }
    }
}
