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
package org.zaproxy.addon.llm.context;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import javax.swing.tree.TreeNode;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteNode;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.model.Context;

public class LlmProjectContextBuilder {

    private static final int DEFAULT_MAX_SITES = 25;
    private static final int DEFAULT_MAX_ALERT_GROUPS = 25;

    private final int maxSites;
    private final int maxAlertGroups;

    public LlmProjectContextBuilder() {
        this(DEFAULT_MAX_SITES, DEFAULT_MAX_ALERT_GROUPS);
    }

    public LlmProjectContextBuilder(int maxSites, int maxAlertGroups) {
        this.maxSites = Math.max(1, maxSites);
        this.maxAlertGroups = Math.max(1, maxAlertGroups);
    }

    public Map<String, Object> buildProjectContext() {
        Session session = Model.getSingleton().getSession();

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("type", "zap_project_context");
        payload.put("session", buildSessionInfo(session));
        payload.put("contexts", buildContextsSummary(session));
        payload.put("sites", buildTopSites(session));
        payload.put("alerts", buildAlertsSummary());
        return payload;
    }

    public Map<String, Object> buildAlertsSummary() {
        ExtensionAlert extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return Map.of("available", false);
        }

        List<Alert> alerts = extAlert.getAllAlerts();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("available", true);
        payload.put("count", alerts.size());

        Map<String, Integer> byRisk = new HashMap<>();
        Map<String, Integer> byName = new HashMap<>();
        for (Alert alert : alerts) {
            byRisk.merge(riskLabel(alert.getRisk()), 1, Integer::sum);
            byName.merge(alert.getName(), 1, Integer::sum);
        }

        payload.put("by_risk", sortCounts(byRisk));
        payload.put(
                "top_names",
                sortCounts(byName).entrySet().stream()
                        .limit(maxAlertGroups)
                        .collect(
                                Collectors.toMap(
                                        Entry::getKey,
                                        Entry::getValue,
                                        (a, b) -> a,
                                        LinkedHashMap::new)));
        payload.put("top_names_truncated", byName.size() > maxAlertGroups);
        return payload;
    }

    private Map<String, Object> buildSessionInfo(Session session) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", session.getSessionName());
        payload.put("id", session.getSessionId());
        payload.put("history_count", getHistoryCount(session));
        return payload;
    }

    private List<Map<String, Object>> buildContextsSummary(Session session) {
        List<Map<String, Object>> contexts = new ArrayList<>();
        for (Context ctx : session.getContexts()) {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("id", ctx.getId());
            c.put("name", ctx.getName());
            c.put("in_scope", ctx.isInScope());
            c.put("include_regexes", ctx.getIncludeInContextRegexs());
            c.put("exclude_regexes", ctx.getExcludeFromContextRegexs());
            contexts.add(c);
        }
        return contexts;
    }

    private List<String> buildTopSites(Session session) {
        List<String> sites = new ArrayList<>();
        if (session.getSiteTree() == null) {
            return sites;
        }
        SiteNode root = session.getSiteTree().getRoot();
        @SuppressWarnings("unchecked")
        Enumeration<TreeNode> children = root.children();
        while (children.hasMoreElements() && sites.size() < maxSites) {
            SiteNode site = (SiteNode) children.nextElement();
            sites.add(site.getHierarchicNodeName(false));
        }
        return sites;
    }

    private static int getHistoryCount(Session session) {
        try {
            return Model.getSingleton()
                    .getDb()
                    .getTableHistory()
                    .getHistoryIds(session.getSessionId())
                    .size();
        } catch (DatabaseException e) {
            return -1;
        }
    }

    private static String riskLabel(int risk) {
        if (risk >= 0 && risk < Alert.MSG_RISK.length) {
            return Alert.MSG_RISK[risk];
        }
        return "Unknown";
    }

    private static Map<String, Integer> sortCounts(Map<String, Integer> counts) {
        return counts.entrySet().stream()
                .sorted(
                        Comparator.<Entry<String, Integer>>comparingInt(Entry::getValue)
                                .reversed()
                                .thenComparing(Entry::getKey))
                .collect(
                        Collectors.toMap(
                                Entry::getKey, Entry::getValue, (a, b) -> a, LinkedHashMap::new));
    }
}
