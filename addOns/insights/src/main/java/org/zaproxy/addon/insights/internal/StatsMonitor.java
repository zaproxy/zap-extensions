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
package org.zaproxy.addon.insights.internal;

import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.zap.authentication.AuthenticationHelper;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.utils.StatsListener;

public class StatsMonitor implements StatsListener, EventConsumer {

    private static final String STATS_CODE_PREFIX = "stats.code.";
    private static final String STATS_ERROR = "stats.log.error";
    private static final String STATS_WARN = "stats.log.warn";
    private static final String STATS_NETWORK_FAILURE = "stats.network.send.failure";
    private static final String STATS_NETWORK_SUCCESS = "stats.network.send.success";
    private static final String STATS_ENDPOINTS_PREFIX = "stats.endpoints.";
    private static final String STATS_ENDPOINTS_TOTAL = STATS_ENDPOINTS_PREFIX + "total";
    private static final String STATS_ENDPOINTS_METHOD_PREFIX = STATS_ENDPOINTS_PREFIX + "method.";
    private static final String STATS_ENDPOINTS_CTYPE_PREFIX = STATS_ENDPOINTS_PREFIX + "ctype.";
    private static final String STATS_RESPONSE_TIME_PREFIX = "stats.responseTime.";

    private static final int MIN_NUMBER_OF_REQS = 1000;
    private static final int MIN_NUMBER_OF_AUTH = 10;

    // TODO move these to options
    private static final int OPTION_LOW_WARNING = 5;
    private static final int OPTION_HIGH_WARNING = 50;
    private static final int OPTION_SLOW_RESPONSE_TIME = 255;

    private InMemoryStats stats = new InMemoryStats();

    private ExtensionInsights ext;

    public StatsMonitor(ExtensionInsights extensionInsights) {
        this.ext = extensionInsights;
    }

    private String getStatsDescription(String key) {
        String msgKey = ExtensionInsights.PREFIX + ".insight." + key;
        if (Constant.messages.containsKey(msgKey)) {
            return Constant.messages.getString(ExtensionInsights.PREFIX + ".insight." + key);
        }
        if (key.startsWith(STATS_CODE_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.stats.code",
                    key.substring(STATS_CODE_PREFIX.length()));
        }
        if (key.startsWith(STATS_ENDPOINTS_METHOD_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.stats.endpoints.method",
                    key.substring(STATS_ENDPOINTS_METHOD_PREFIX.length()));
        }
        if (key.startsWith(STATS_ENDPOINTS_CTYPE_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.stats.endpoints.ctype",
                    key.substring(STATS_ENDPOINTS_CTYPE_PREFIX.length()));
        }
        return key;
    }

    private long unbox(Long l) {
        return l == null ? 0 : l;
    }

    private void recordNonZeroInsight(Insight.Level level, String key) {
        long val = unbox(stats.getStat(key));
        if (val > 0) {
            recordInsight(level, key, val);
        }
    }

    private void recordInsight(Insight.Level level, String key, long stat) {
        this.recordInsight(level, "", key, stat);
    }

    private void recordInsight(Insight.Level level, String site, String key, long stat) {
        ext.recordInsight(new Insight(level, site, key, getStatsDescription(key), stat));
    }

    public void processStats() {
        processStatusCodeStats();
        processEndpointStats();
        processNetworkStats();
        processResponseTimeStats();
        processAuthStats();

        // ZAP errors and warnings
        recordNonZeroInsight(Insight.Level.Low, STATS_ERROR);
        recordNonZeroInsight(Insight.Level.Low, STATS_WARN);
    }

    private void processStatusCodeStats() {
        // Count of responses by site and status code
        Map<String, Map<String, Long>> siteCodeStats = stats.getAllSiteStats(STATS_CODE_PREFIX);
        for (Entry<String, Map<String, Long>> site2stats : siteCodeStats.entrySet()) {
            String site = site2stats.getKey();
            // Record all stats by
            long total = 0;
            long tot400 = 0;
            long tot500 = 0;

            for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                recordInsight(Insight.Level.Info, site, k2stat.getKey(), k2stat.getValue());
                total += k2stat.getValue();
                if (k2stat.getKey().startsWith(STATS_CODE_PREFIX + "4")) {
                    tot400 += k2stat.getValue();
                } else if (k2stat.getKey().startsWith(STATS_CODE_PREFIX + "5")) {
                    tot500 += k2stat.getValue();
                }
            }

            if (total > MIN_NUMBER_OF_REQS && tot400 > total * OPTION_LOW_WARNING / 100) {
                recordInsight(
                        Insight.Level.Low, site, STATS_CODE_PREFIX + "4xx", tot400 * 100 / total);
            }
            if (total > MIN_NUMBER_OF_REQS && tot500 > total * OPTION_LOW_WARNING / 100) {
                recordInsight(
                        Insight.Level.Low, site, STATS_CODE_PREFIX + "5xx", tot500 * 100 / total);
            }
        }
    }

    private void processEndpointStats() {
        // Count endpoints related stats
        Map<String, Map<String, Long>> siteEndpointStats =
                stats.getAllSiteStats(STATS_ENDPOINTS_PREFIX);
        for (Entry<String, Map<String, Long>> site2stats : siteEndpointStats.entrySet()) {
            String site = site2stats.getKey();
            for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                recordInsight(Insight.Level.Info, site, k2stat.getKey(), k2stat.getValue());
            }
        }
    }

    private void recordInsightWithLimits(
            String site, String keyPrefix, long min, long total, long bad) {
        if (total < min) {
            return;
        }
        if (bad > 0) {
            recordInsight(Insight.Level.Info, site, keyPrefix + "info", bad);
        }

        if (bad > total * OPTION_LOW_WARNING / 100) {
            recordInsight(Insight.Level.Low, site, keyPrefix + "low", bad * 100 / total);
        }
        if (bad > total * OPTION_HIGH_WARNING / 100) {
            recordInsight(Insight.Level.Medium, site, keyPrefix + "medium", bad * 100 / total);
        }
    }

    private void processNetworkStats() {
        // Network problems
        long netGood = unbox(stats.getStat(STATS_NETWORK_SUCCESS));
        long netBad = unbox(stats.getStat(STATS_NETWORK_FAILURE));
        long netTotal = netGood + netBad;

        recordInsightWithLimits("", "stats.network.failure.", MIN_NUMBER_OF_REQS, netTotal, netBad);
    }

    private void processResponseTimeStats() {
        Map<String, Map<String, Long>> siteCodeStats =
                stats.getAllSiteStats(STATS_RESPONSE_TIME_PREFIX);
        for (Entry<String, Map<String, Long>> site2stats : siteCodeStats.entrySet()) {
            String site = site2stats.getKey();
            long total = 0;
            long slowResponses = 0;

            for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                String timeStr = k2stat.getKey().substring(STATS_RESPONSE_TIME_PREFIX.length());
                total += k2stat.getValue();
                try {
                    int time = Integer.parseInt(timeStr);
                    if (time > OPTION_SLOW_RESPONSE_TIME) {
                        slowResponses += k2stat.getValue();
                    }
                } catch (NumberFormatException e) {
                    // Ignore
                }
            }

            recordInsightWithLimits(
                    site, "stats.responseTime.", MIN_NUMBER_OF_REQS, total, slowResponses);
        }
    }

    private void processAuthStats() {
        Map<String, Map<String, Long>> siteEndpointStats = stats.getAllSiteStats("stats.auth.");
        for (Entry<String, Map<String, Long>> site2stats : siteEndpointStats.entrySet()) {
            String site = site2stats.getKey();
            long failure = 0;
            long success = 0;

            for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                switch (k2stat.getKey()) {
                    case AuthenticationHelper.AUTH_FAILURE_STATS:
                        failure = k2stat.getValue();
                        break;
                    case AuthenticationHelper.AUTH_SUCCESS_STATS:
                        success = k2stat.getValue();
                        break;
                }
            }
            recordInsightWithLimits(
                    site, "stats.auth.failure.", MIN_NUMBER_OF_AUTH, failure + success, failure);
        }
    }

    private boolean isRelevant(String key) {
        return key.startsWith(STATS_CODE_PREFIX)
                || key.startsWith(STATS_RESPONSE_TIME_PREFIX)
                || key.equals(AuthenticationHelper.AUTH_FAILURE_STATS)
                || key.equals(AuthenticationHelper.AUTH_SUCCESS_STATS)
                || key.equals(STATS_NETWORK_SUCCESS)
                || key.equals(STATS_NETWORK_FAILURE)
                || key.equals(STATS_ERROR)
                || key.equals(STATS_WARN);
    }

    @Override
    public void eventReceived(Event event) {
        String site;
        try {
            HistoryReference href = event.getTarget().getStartNode().getHistoryReference();
            site = SessionStructure.getHostName(href.getURI());
            stats.counterInc(site, STATS_ENDPOINTS_TOTAL);
            stats.counterInc(site, STATS_ENDPOINTS_METHOD_PREFIX + href.getMethod());

            Map<String, String> params = event.getParameters();
            if (params != null && params.containsKey("contentType")) {
                String ct = params.get("contentType");
                int semicolonIdx = ct.indexOf(';');
                if (semicolonIdx > 0) {
                    ct = ct.substring(0, semicolonIdx);
                }
                stats.counterInc(site, STATS_ENDPOINTS_CTYPE_PREFIX + ct);
            }
        } catch (URIException e) {
            // Ignore
        }
    }

    @Override
    public void counterInc(String key) {
        if (isRelevant(key)) {
            stats.counterInc(key);
        }
    }

    @Override
    public void counterInc(String site, String key) {
        if (isRelevant(key)) {
            stats.counterInc(site, key);
        }
    }

    @Override
    public void counterInc(String key, long inc) {
        if (isRelevant(key)) {
            stats.counterInc(key, inc);
        }
    }

    @Override
    public void counterInc(String site, String key, long inc) {
        if (isRelevant(key)) {
            stats.counterInc(site, key, inc);
        }
    }

    @Override
    public void counterDec(String key) {
        if (isRelevant(key)) {
            stats.counterDec(key);
        }
    }

    @Override
    public void counterDec(String site, String key) {
        if (isRelevant(key)) {
            stats.counterDec(site, key);
        }
    }

    @Override
    public void counterDec(String key, long dec) {
        if (isRelevant(key)) {
            stats.counterDec(key, dec);
        }
    }

    @Override
    public void counterDec(String site, String key, long dec) {
        if (isRelevant(key)) {
            stats.counterDec(site, key, dec);
        }
    }

    @Override
    public void highwaterMarkSet(String key, long value) {
        if (isRelevant(key)) {
            stats.highwaterMarkSet(key, value);
        }
    }

    @Override
    public void highwaterMarkSet(String site, String key, long value) {
        if (isRelevant(key)) {
            stats.highwaterMarkSet(site, key, value);
        }
    }

    @Override
    public void lowwaterMarkSet(String key, long value) {
        if (isRelevant(key)) {
            stats.lowwaterMarkSet(key, value);
        }
    }

    @Override
    public void lowwaterMarkSet(String site, String key, long value) {
        if (isRelevant(key)) {
            stats.lowwaterMarkSet(site, key, value);
        }
    }

    @Override
    public void allCleared() {
        stats.allCleared();
        ext.clearInsights();
    }

    @Override
    public void allCleared(String site) {
        stats.allCleared(site);
    }

    @Override
    public void cleared(String keyPrefix) {
        stats.cleared(keyPrefix);
    }

    @Override
    public void cleared(String site, String keyPrefix) {
        stats.cleared(site, keyPrefix);
    }
}
