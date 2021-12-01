/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.ReportData;
import org.zaproxy.zap.extension.alert.AlertNode;

/**
 * The SARIF data structure needs GUIDs, has multiple references etc. inside which are not available
 * from standard OWASP ZAP report data.<br>
 * <br>
 * So this class gives support to access SARIF related parts inside templates easily.
 */
public class SarifReportDataSupport {

    private ReportData reportData;
    private List<SarifResult> results;

    // we use a sorted map here, so values set will always be sorted available - so
    // same report will produce same
    // ordering etc.
    private SortedMap<Integer, SarifRule> rulesMap;
    private Collection<SarifTaxonomy> taxonomies;

    public SarifReportDataSupport(ReportData reportData) {
        this.reportData = reportData;
    }

    public SarifToolData getComponents() {
        return SarifToolData.INSTANCE;
    }

    public List<SarifResult> getResults() {
        if (results == null) {
            results = createResults();
        }
        return results;
    }

    private List<SarifResult> createResults() {
        List<SarifResult> results = new ArrayList<>();

        List<Alert> allAlerts = collectAllAlerts(reportData.getAlertTreeRootNode());

        for (Alert alert : allAlerts) {
            SarifResult sarifResult = SarifResult.builder().setAlert(alert).build();
            results.add(sarifResult);
        }

        /* sort, so always in same order */
        Collections.sort(results);

        return results;
    }

    public Collection<SarifTaxonomy> getTaxonomies() {
        if (taxonomies == null) {
            taxonomies = createTaxonomies();
        }
        return taxonomies;
    }

    private Collection<SarifTaxonomy> createTaxonomies() {
        List<SarifTaxonomy> list = new ArrayList<>();

        /* currently we provide only CWE */
        createCWETaxonomy(list);

        return list;
    }

    private List<Alert> collectAllAlerts(AlertNode rootNode) {
        List<Alert> list = new ArrayList<>();

        for (int alertIndex = 0; alertIndex < rootNode.getChildCount(); alertIndex++) {
            AlertNode alertNode = rootNode.getChildAt(alertIndex);
            for (int instIndex = 0; instIndex < alertNode.getChildCount(); instIndex++) {
                AlertNode instanceNode = alertNode.getChildAt(instIndex);
                list.add(instanceNode.getUserObject());
            }
        }
        return list;
    }

    private void createCWETaxonomy(List<SarifTaxonomy> list) {
        SarifTaxonomy taxonomy = new SarifTaxonomy(SarifToolData.INSTANCE.getCwe());
        list.add(taxonomy);

        Set<Integer> foundCWEIds = new TreeSet<>();
        List<Alert> allAlerts = collectAllAlerts(reportData.getAlertTreeRootNode());

        for (Alert alert : allAlerts) {
            foundCWEIds.add(alert.getCweId());
        }

        for (Integer foundCWEId : foundCWEIds) {
            SarifTaxa taxa = taxonomy.addTaxa("" + foundCWEId);
            taxa.helpUri = "https://cwe.mitre.org/data/definitions/" + foundCWEId + ".html";
        }
    }

    /** @return a sorted collection of SARIF rules */
    public Collection<SarifRule> getRules() {
        if (rulesMap == null) {
            rulesMap = createRules();
        }
        return rulesMap.values();
    }

    private SortedMap<Integer, SarifRule> createRules() {
        SortedMap<Integer, SarifRule> registeredRules = new TreeMap<>();

        List<Alert> alerts = collectAllAlerts(reportData.getAlertTreeRootNode());
        for (Alert alert : alerts) {

            int pluginId = alert.getPluginId();
            if (registeredRules.containsKey(pluginId)) {
                // already registered
                continue;
            }
            // create and register the rule
            SarifRule rule = new SarifRule(alert);
            registeredRules.put(pluginId, rule);
        }

        return registeredRules;
    }
}
