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

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
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
 * from standard ZAP report data.<br>
 * <br>
 * So this class gives support to access SARIF related parts inside templates easily.
 */
public class SarifReportDataSupport {

    private static final String FALLBACK_SEMANTIC_VERSION = "0.0.0";
    private ReportData reportData;
    private List<SarifResult> results;

    // we use a sorted map here, so values set will always be sorted available - so
    // same report will produce same ordering etc.
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

        Collection<Alert> allAlerts = collectAllAlerts(reportData.getAlertTreeRootNode());
        List<SarifResult> results = new ArrayList<>(allAlerts.size());

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
        createCweTaxonomy(list);

        return list;
    }

    private Collection<Alert> collectAllAlerts(AlertNode rootNode) {
        List<Alert> list = new LinkedList<>();

        for (int alertIndex = 0; alertIndex < rootNode.getChildCount(); alertIndex++) {
            AlertNode alertNode = rootNode.getChildAt(alertIndex);
            for (int instIndex = 0; instIndex < alertNode.getChildCount(); instIndex++) {
                AlertNode instanceNode = alertNode.getChildAt(instIndex);
                list.add(instanceNode.getUserObject());
            }
        }
        return list;
    }

    private void createCweTaxonomy(List<SarifTaxonomy> list) {
        SarifTaxonomy taxonomy = new SarifTaxonomy(SarifToolData.INSTANCE.getCwe());
        list.add(taxonomy);

        Set<Integer> foundCWEIds = new TreeSet<>();
        Collection<Alert> allAlerts = collectAllAlerts(reportData.getAlertTreeRootNode());

        for (Alert alert : allAlerts) {
            foundCWEIds.add(alert.getCweId());
        }

        for (Integer foundCWEId : foundCWEIds) {
            SarifTaxa taxa = taxonomy.addTaxa("" + foundCWEId);
            taxa.helpUri =
                    URI.create("https://cwe.mitre.org/data/definitions/" + foundCWEId + ".html");
        }
    }

    /**
     * @return a sorted collection of SARIF rules
     */
    public Collection<SarifRule> getRules() {
        if (rulesMap == null) {
            rulesMap = createRules();
        }
        return rulesMap.values();
    }

    private SortedMap<Integer, SarifRule> createRules() {
        SortedMap<Integer, SarifRule> registeredRules = new TreeMap<>();

        Collection<Alert> alerts = collectAllAlerts(reportData.getAlertTreeRootNode());
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

    /**
     * Ensures given tool version is compatible with SARIF tool versions. This method ensures, that
     * even for reports created with ZAP developer builds the <a
     * href="https://sarifweb.azurewebsites.net/Validation">SARIF online validation</a> shall have
     * no validation errors.<br>
     * <br>
     * To ensure this, this method returns a result version which is compatible to <a
     * href="https://semver.org">Semantic Versioning 2.0.0</a>.
     *
     * <p>This method will do following: If the given version ($givenVersion) cannot be represented
     * in a semantic version string like "$major.$minor.$hotfix", "$major" or "$major.minor" the
     * result will always be a fallback to {@value #FALLBACK_SEMANTIC_VERSION}-$givenVersion
     */
    public String ensureSemanticVersion(String toolVersion) {
        if (toolVersion != null) {

            StringBuilder sb = new StringBuilder();
            String[] splitted = toolVersion.split("\\.");

            boolean failed = false;

            for (String splitPart : splitted) {
                try {
                    int value = Integer.parseInt(splitPart);
                    if (sb.length() > 0) {
                        sb.append('.');
                    }
                    sb.append(value);
                } catch (NumberFormatException e) {
                    failed = true;
                    break;
                }
            }
            if (!failed) {
                return sb.toString();
            }
        }
        return FALLBACK_SEMANTIC_VERSION + "-" + toolVersion;
    }
}
