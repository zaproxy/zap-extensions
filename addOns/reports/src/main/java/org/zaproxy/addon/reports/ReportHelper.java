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

import java.util.Collections;
import java.util.Map;
import org.apache.commons.httpclient.HttpStatus;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class ReportHelper {

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
        String[] schemeHostPort = site.split(":");
        // http://www.example.com:8080 - the host will start with //
        return schemeHostPort[1].substring(2);
    }

    public static int getPortForSite(String site) {
        String[] schemeHostPort = site.split(":");
        if (schemeHostPort.length == 3) {
            return Integer.parseInt(schemeHostPort[2]);
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
        return HttpStatus.getStatusText(code);
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
}
