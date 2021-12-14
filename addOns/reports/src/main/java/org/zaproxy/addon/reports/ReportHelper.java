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
package org.zaproxy.addon.reports;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.commons.text.StringEscapeUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.reports.sarif.SarifReportDataSupport;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.XMLStringUtil;

public class ReportHelper {

    /**
     * For some reports there is additional tooling necessary - e.g. for SARIF: Because the data
     * structure is completely different to standard OWASP ZAP model and would lead to unreadable
     * and nearly unmaintainable report templates.<br>
     * <br>
     * The benefit here is, that the support objects are only created when wanted by the dedicated
     * template (so lazy).<br>
     * <br>
     * Supported IDs:
     *
     * <ul>
     *   <li><code>sarif</code> - creates a {@link SarifReportDataSupport} object for SARIF
     *       reporting.
     * </ul>
     *
     * @param id identifier for the support object to create
     * @param reportData ZAP report data object
     * @return support object
     * @throws IllegalArgumentException when support with given id is not available
     */
    public static Object createSupport(String id, ReportData reportData) {
        switch (id) {
            case "sarif":
                return new SarifReportDataSupport(reportData);
            default:
                throw new IllegalArgumentException("No support available for id:" + id);
        }
    }

    public static String getRiskString(int risk) {
        return Constant.messages.getString(ExtensionReports.PREFIX + ".report.risk." + risk);
    }

    public static String getConfidenceString(int confidence) {
        return Constant.messages.getString(
                ExtensionReports.PREFIX + ".report.confidence." + confidence);
    }

    public static String getStatisticsString(String statsKey) {
        return Constant.messages.getString(ExtensionReports.PREFIX + ".report." + statsKey);
    }

    public static String getHostForSite(String site) {
        if (site == null) {
            return "";
        }
        String host = site;
        if (site.contains(":")) {
            String[] schemeHostPort = site.split(":");
            String start = schemeHostPort[0].toLowerCase();
            if (start.equals("http")
                    || start.equals("https") && schemeHostPort[1].startsWith("//")) {
                // http://www.example.com:8080 - the host will start with //
                host = schemeHostPort[1].substring(2);
            }
        }
        int slashIndex = host.indexOf("/");
        if (slashIndex > 0) {
            host = host.substring(0, slashIndex);
        }
        return host;
    }

    public static int getPortForSite(String site) {
        if (site == null) {
            return 80;
        }
        String[] schemeHostPort = site.split(":");
        if (schemeHostPort.length == 3) {
            try {
                return Integer.parseInt(schemeHostPort[2]);
            } catch (NumberFormatException e) {
                // Ignore
            }
        }
        if (schemeHostPort[0].equalsIgnoreCase("https")) {
            return 443;
        }
        return 80;
    }

    public static boolean isSslSite(String site) {
        String[] schemeHostPort = site.split(":");
        return schemeHostPort[0].equalsIgnoreCase("https");
    }

    public static String getHttpStatusCodeString(int code) {
        return HttpStatusReason.get(code);
    }

    public static Map<String, Long> getSiteStats(String site, String prefix) {
        ExtensionStats extStats =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);
        if (extStats != null) {
            InMemoryStats stats = extStats.getInMemoryStats();
            if (stats != null) {
                return stats.getSiteStats(site, prefix);
            }
        }
        return Collections.emptyMap();
    }

    public static boolean hasSiteStats(String site, String prefix) {
        return !getSiteStats(site, prefix).isEmpty();
    }

    public static List<Alert> getAlertsForSite(AlertNode rootNode, String site) {
        List<Alert> list = new ArrayList<>();

        for (int alertIndex = 0; alertIndex < rootNode.getChildCount(); alertIndex++) {
            AlertNode alertNode = rootNode.getChildAt(alertIndex);
            for (int instIndex = 0; instIndex < alertNode.getChildCount(); instIndex++) {
                AlertNode instanceNode = alertNode.getChildAt(instIndex);
                if (instanceNode.getUserObject().getUri().startsWith(site)) {
                    list.add(instanceNode.getUserObject());
                    break;
                }
            }
        }
        return list;
    }

    /**
     * @deprecated Use {@link getAlertInstancesForSite(AlertNode, String, String int)} instead -
     *     this method can return the instances for different alerts with the same pluginId.
     */
    @Deprecated
    public static List<Alert> getAlertInstancesForSite(
            AlertNode rootNode, String site, int pluginId) {
        List<Alert> list = new ArrayList<>();

        for (int alertIndex = 0; alertIndex < rootNode.getChildCount(); alertIndex++) {
            AlertNode alertNode = rootNode.getChildAt(alertIndex);
            // Only the instances have userObjects, not the top level nodes :/
            if (alertNode.getChildAt(0) != null
                    && alertNode.getChildAt(0).getUserObject().getPluginId() == pluginId) {
                for (int instIndex = 0; instIndex < alertNode.getChildCount(); instIndex++) {
                    AlertNode instanceNode = alertNode.getChildAt(instIndex);
                    if (instanceNode.getUserObject().getUri().startsWith(site)) {
                        list.add(instanceNode.getUserObject());
                    }
                }
                break;
            }
        }
        return list;
    }

    public static List<Alert> getAlertInstancesForSite(
            AlertNode rootNode, String site, String alertName, int alertRisk) {
        List<Alert> list = new ArrayList<>();

        for (int alertIndex = 0; alertIndex < rootNode.getChildCount(); alertIndex++) {
            AlertNode alertNode = rootNode.getChildAt(alertIndex);
            // Only the instances have userObjects, not the top level nodes :/
            if (alertNode.getChildAt(0) != null
                    && alertNode.getRisk() == alertRisk
                    && alertNode.getChildAt(0).getUserObject().getName().equals(alertName)) {
                for (int instIndex = 0; instIndex < alertNode.getChildCount(); instIndex++) {
                    AlertNode instanceNode = alertNode.getChildAt(instIndex);
                    if (instanceNode.getUserObject().getUri().startsWith(site)) {
                        list.add(instanceNode.getUserObject());
                    }
                }
                break;
            }
        }
        return list;
    }

    /** A method which mimics the escaping used for traditional ZAP reports */
    public static String legacyEscapeText(String text) {
        return legacyEscapeText(text, false);
    }

    /** A method which mimics the escaping used for traditional ZAP reports */
    public static String legacyEscapeText(String text, boolean escapeJson) {
        String enc = XMLStringUtil.escapeControlChrs(text);
        if (escapeJson) {
            return StringEscapeUtils.escapeJava(enc);
        }
        return enc;
    }

    /** A method which mimics the escaping used for traditional ZAP reports */
    public static String legacyEscapeParagraph(String text) {
        return legacyEscapeParagraph(text, false);
    }

    /** A method which mimics the escaping used for traditional ZAP reports */
    public static String legacyEscapeParagraph(String text, boolean escapeJson) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return legacyEscapeText(
                        "<p>"
                                + text.replaceAll("\\r\\n", "</p><p>").replaceAll("\\n", "</p><p>")
                                + "</p>",
                        escapeJson)
                .replace("&lt;p&gt;", "<p>")
                .replace("&lt;/p&gt;", "</p>");
    }
}
