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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.AlertNode;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.XMLStringUtil;

public class ReportHelper {

    private static final Logger LOGGER = LogManager.getLogger(ReportHelper.class);

    private static final String STATS_RESOURCE_PREFIX = ExtensionReports.PREFIX + ".report.";

    public static String getRiskString(int risk) {
        return Constant.messages.getString(ExtensionReports.PREFIX + ".report.risk." + risk);
    }

    public static String getConfidenceString(int confidence) {
        return Constant.messages.getString(
                ExtensionReports.PREFIX + ".report.confidence." + confidence);
    }

    public static String getStatisticsString(String statsKey) {
        String resourceKey = STATS_RESOURCE_PREFIX + statsKey;
        if (Constant.messages.containsKey(resourceKey)) {
            return Constant.messages.getString(resourceKey);
        }
        return statsKey;
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

        try {
            var uri = new URI(site);
            int port = uri.getPort();
            if (port != -1) {
                return port;
            }

            return getPortFromScheme(site);

        } catch (URISyntaxException e) {
            return getPortFromScheme(site);
        }
    }

    private static int getPortFromScheme(String site) {
        if (StringUtils.startsWithIgnoreCase(site, "https")) {
            return 443;
        } else {
            return 80;
        }
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

    public static Map<String, Long> getGlobalStats(String prefix) {
        ExtensionStats extStats =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);
        if (extStats != null) {
            InMemoryStats stats = extStats.getInMemoryStats();
            if (stats != null) {
                return stats.getStats(prefix);
            }
        }
        return Collections.emptyMap();
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
     * @deprecated Use {@link #getAlertInstancesForSite(AlertNode, String, String, int)} instead -
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

    public static List<AlertNode> getChildren(AlertNode node, boolean incLeaves) {
        List<AlertNode> list = new ArrayList<>();
        Enumeration<?> children = node.children();
        while (children.hasMoreElements()) {
            AlertNode childNode = (AlertNode) children.nextElement();
            if (incLeaves || !childNode.isLeaf() && !node.equals(childNode)) {
                list.add(childNode);
            }
        }

        return list;
    }

    public static List<AlertNode> getDepthFirstChildren(AlertNode node, boolean incLeaves) {
        List<AlertNode> list = new ArrayList<>();
        Enumeration<?> children = node.depthFirstEnumeration();
        while (children.hasMoreElements()) {
            AlertNode childNode = (AlertNode) children.nextElement();
            if (incLeaves || !childNode.isLeaf() && !node.equals(childNode)) {
                list.add(childNode);
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

    // XXX Workaround for https://github.com/thymeleaf/thymeleaf-spring/issues/275
    // Calling Alert.getParam() directly in the JSON reports leads to the issue, so move the call
    // here instead.
    public static String legacyEscapeTextAlertParam(Alert alert, boolean escapeJson) {
        return legacyEscapeText(alert.getParam(), escapeJson);
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

    public static String escapeXml(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        return XMLStringUtil.escapeControlChrs(text);
    }

    /**
     * Gets the HTTP message with the given ID.
     *
     * @param id the ID of the message.
     * @return the message, or {@code null} if it no longer exists or an error occurred.
     * @since 0.38.0
     */
    public static HttpMessage getHttpMessage(int id) {
        try {
            return new HistoryReference(id, true).getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            LOGGER.debug("An error occurred while reading the HTTP message:", e);
        }
        return null;
    }
}
