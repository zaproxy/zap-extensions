/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.report;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthReportData {

    private String site;
    private boolean validReport;
    private String afEnv;
    private List<SummaryItem> summaryItems = new ArrayList<>();
    private Map<String, StatsItem> statistics = new TreeMap<>();
    private List<String> nextSteps = new ArrayList<>();

    public void addSummaryItem(boolean passed, String key, String description) {
        summaryItems.add(new SummaryItem(passed, key, description));
    }

    public void addStatsItem(String key, String scope, long value) {
        statistics.put(key, new StatsItem(key, scope, value));
    }

    public Object[] getStatistics() {
        return statistics.values().toArray();
    }

    public record SummaryItem(boolean passed, String key, String description) {}

    public record StatsItem(String key, String scope, long value) {}
}
