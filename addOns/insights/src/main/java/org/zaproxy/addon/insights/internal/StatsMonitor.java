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

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    private static final Logger LOGGER = LogManager.getLogger(StatsMonitor.class);

    private static final String INSIGHT_CODE_PREFIX = "insight.code.";

    private static final String INSIGHT_ENDPOINTS_PREFIX = "insight.endpoint.";
    private static final String INSIGHTS_ENDPOINTS_TOTAL = INSIGHT_ENDPOINTS_PREFIX + "total";
    private static final String INSIGHTS_ENDPOINTS_METHOD_PREFIX =
            INSIGHT_ENDPOINTS_PREFIX + "method.";
    private static final String INSIGHTS_ENDPOINTS_CTYPE_PREFIX =
            INSIGHT_ENDPOINTS_PREFIX + "ctype.";

    private static final String STATS_CODE_PREFIX = "stats.code.";
    private static final String STATS_ERROR = "stats.log.error";
    private static final String STATS_WARN = "stats.log.warn";
    private static final String STATS_NETWORK_FAILURE = "stats.network.send.failure";
    private static final String STATS_NETWORK_SUCCESS = "stats.network.send.success";

    private static final String STATS_DATABASE_FULL = "stats.error.database.full";
    private static final String STATS_DISKSPACE_FULL = "stats.error.diskspace.full";

    private static final String STATS_RESPONSE_TIME_PREFIX = "stats.responseTime.";

    private static final int MIN_NUMBER_OF_REQS = 1000;
    private static final int MIN_NUMBER_OF_AUTH = 10;

    private static final long MEM_GC_CHECK_MSEC = TimeUnit.MINUTES.toMillis(1);

    private InMemoryStats stats = new InMemoryStats();
    private long lastGc;

    private ExtensionInsights ext;

    public StatsMonitor(ExtensionInsights extensionInsights) {
        this.ext = extensionInsights;
    }

    private String getStatsDescription(String key) {
        String msgKey = ExtensionInsights.PREFIX + "." + key;
        if (Constant.messages.containsKey(msgKey)) {
            return Constant.messages.getString(msgKey);
        }
        if (key.startsWith(INSIGHT_CODE_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.code",
                    key.substring(INSIGHT_CODE_PREFIX.length()));
        }
        if (key.startsWith(INSIGHTS_ENDPOINTS_METHOD_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.endpoint.method",
                    key.substring(INSIGHTS_ENDPOINTS_METHOD_PREFIX.length()));
        }
        if (key.startsWith(INSIGHTS_ENDPOINTS_CTYPE_PREFIX)) {
            return Constant.messages.getString(
                    ExtensionInsights.PREFIX + ".insight.endpoint.ctype",
                    key.substring(INSIGHTS_ENDPOINTS_CTYPE_PREFIX.length()));
        }
        return key;
    }

    private long unbox(Long l) {
        return l == null ? 0 : l;
    }

    private void recordWarningStatsInsight(
            Insight.Level level, String statsKey, String insightsKey) {
        recordInsight(
                level, Insight.Reason.WARNING, insightsKey, unbox(stats.getStat(statsKey)), 0);
    }

    private void recordInsight(
            Insight.Level level, Insight.Reason reason, String key, long stat, long total) {
        this.recordInsight(level, reason, "", key, stat, total);
    }

    private void recordInsight(
            Insight.Level level, Insight.Reason reason, String site, String key, long stat) {
        this.recordInsight(level, reason, site, key, stat, 0);
    }

    private void recordInsight(
            Insight.Level level,
            Insight.Reason reason,
            String site,
            String key,
            long stat,
            long total) {
        if (stat == 0) {
            // Ignore - no such stat, or percentage less than 1
            return;
        }
        boolean isPercent = total > 0;
        long value = isPercent ? percent(stat, total) : stat;
        if (value > 0) {
            ext.recordInsight(
                    new Insight(
                            level, reason, site, key, getStatsDescription(key), value, isPercent));
        }
    }

    public void processStats() {
        processStatusCodeStats();
        processEndpointStats();
        processNetworkStats();
        processResponseTimeStats();
        processAuthStats();

        // ZAP errors and warnings
        recordWarningStatsInsight(Insight.Level.LOW, STATS_ERROR, "insight.log.error");
        recordWarningStatsInsight(Insight.Level.LOW, STATS_WARN, "insight.log.warn");
        recordWarningStatsInsight(Insight.Level.HIGH, STATS_DATABASE_FULL, "insight.database.full");
        recordWarningStatsInsight(
                Insight.Level.HIGH, STATS_DISKSPACE_FULL, "insight.diskspace.full");

        checkMemoryUsage();
    }

    private static long percent(long value, long total) {
        return value * 100 / total;
    }

    private void processStatusCodeStats() {
        // Count of responses by site and status code
        Map<String, Map<String, Long>> siteCodeStats = stats.getAllSiteStats(STATS_CODE_PREFIX);
        for (Entry<String, Map<String, Long>> site2stats : siteCodeStats.entrySet()) {
            String site = site2stats.getKey();
            long total = 0;
            Map<String, Long> codeCounts = new HashMap<>();

            for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                // Summarise by 1xx, 2xx etc
                String key =
                        k2stat.getKey()
                                .substring(
                                        STATS_CODE_PREFIX.length(), STATS_CODE_PREFIX.length() + 1);
                codeCounts.merge(key, k2stat.getValue(), Long::sum);
                total += k2stat.getValue();
            }

            for (Entry<String, Long> entry : codeCounts.entrySet()) {
                recordInsight(
                        Insight.Level.INFO,
                        Insight.Reason.INFO,
                        site,
                        INSIGHT_CODE_PREFIX + entry.getKey() + "xx",
                        entry.getValue(),
                        total);
            }
            recordMessageInsightWithLimits(
                    Insight.Level.INFO,
                    Insight.Level.LOW,
                    site,
                    INSIGHT_CODE_PREFIX + "4xx",
                    MIN_NUMBER_OF_REQS,
                    total,
                    unbox(codeCounts.get("4")));

            recordMessageInsightWithLimits(
                    Insight.Level.INFO,
                    Insight.Level.LOW,
                    site,
                    INSIGHT_CODE_PREFIX + "5xx",
                    MIN_NUMBER_OF_REQS,
                    total,
                    unbox(codeCounts.get("5")));
        }
    }

    private void processEndpointStats() {
        // Count endpoints related stats
        Map<String, Map<String, Long>> siteEndpointStats =
                stats.getAllSiteStats(INSIGHT_ENDPOINTS_PREFIX);
        for (Entry<String, Map<String, Long>> site2stats : siteEndpointStats.entrySet()) {
            String site = site2stats.getKey();

            Long total = site2stats.getValue().get(INSIGHTS_ENDPOINTS_TOTAL);
            if (total != null) {
                recordInsight(
                        Insight.Level.INFO,
                        Insight.Reason.INFO,
                        site,
                        INSIGHTS_ENDPOINTS_TOTAL,
                        total);

                for (Entry<String, Long> k2stat : site2stats.getValue().entrySet()) {
                    if (!INSIGHTS_ENDPOINTS_TOTAL.equals(k2stat.getKey())) {
                        recordInsight(
                                Insight.Level.INFO,
                                Insight.Reason.INFO,
                                site,
                                k2stat.getKey(),
                                k2stat.getValue(),
                                total);
                    }
                }
            }
        }
    }

    private void recordMessageInsightWithLimits(
            Insight.Level lowLevel,
            Insight.Level highLevel,
            String site,
            String key,
            long min,
            long total,
            long bad) {
        if (bad > 0) {
            recordInsight(Insight.Level.INFO, Insight.Reason.INFO, site, key, bad, total);
        }

        if (total < min) {
            return;
        }

        if (bad >= total * ext.getParam().getMessagesHighThreshold() / 100) {
            recordInsight(highLevel, Insight.Reason.EXCEEDED_HIGH, site, key, bad, total);
        } else if (bad >= total * ext.getParam().getMessagesLowThreshold() / 100) {
            recordInsight(lowLevel, Insight.Reason.EXCEEDED_LOW, site, key, bad, total);
        }
    }

    private void processNetworkStats() {
        // Network problems
        long netGood = unbox(stats.getStat(STATS_NETWORK_SUCCESS));
        long netBad = unbox(stats.getStat(STATS_NETWORK_FAILURE));
        long netTotal = netGood + netBad;

        recordMessageInsightWithLimits(
                Insight.Level.LOW,
                Insight.Level.MEDIUM,
                "",
                "insight.network.failure",
                MIN_NUMBER_OF_REQS,
                netTotal,
                netBad);
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
                    if (time >= ext.getParam().getSlowResponse()) {
                        slowResponses += k2stat.getValue();
                    }
                } catch (NumberFormatException e) {
                    // Ignore
                }
            }

            recordMessageInsightWithLimits(
                    Insight.Level.INFO,
                    Insight.Level.LOW,
                    site,
                    "insight.response.slow",
                    MIN_NUMBER_OF_REQS,
                    total,
                    slowResponses);
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
            recordMessageInsightWithLimits(
                    Insight.Level.LOW,
                    Insight.Level.MEDIUM,
                    site,
                    "insight.auth.failure",
                    MIN_NUMBER_OF_AUTH,
                    failure + success,
                    failure);
        }
    }

    private void checkMemoryUsage() {
        MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();

        long usage = percent(heap.getUsed(), heap.getMax());

        if (usage >= ext.getParam().getMemoryHighThreshold()
                && System.currentTimeMillis() - lastGc > MEM_GC_CHECK_MSEC) {
            LOGGER.info("Running GC as memory usage at {}%", usage);
            System.gc();
            lastGc = System.currentTimeMillis();
            usage = percent(heap.getUsed(), heap.getMax());
        }
        LOGGER.debug("Memory usage at {}%", usage);

        if (usage >= ext.getParam().getMemoryLowThreshold()) {
            Insight.Level level = Insight.Level.MEDIUM;
            Insight.Reason reason = Insight.Reason.EXCEEDED_LOW;
            if (usage >= ext.getParam().getMemoryHighThreshold()) {
                level = Insight.Level.HIGH;
                reason = Insight.Reason.EXCEEDED_HIGH;
            }
            recordInsight(level, reason, "", "insight.memory.usage", usage);
        }
    }

    private boolean isRelevant(String key) {
        return key.startsWith(STATS_CODE_PREFIX)
                || key.startsWith(STATS_RESPONSE_TIME_PREFIX)
                || key.equals(AuthenticationHelper.AUTH_FAILURE_STATS)
                || key.equals(AuthenticationHelper.AUTH_SUCCESS_STATS)
                || key.equals(STATS_DATABASE_FULL)
                || key.equals(STATS_DISKSPACE_FULL)
                || key.equals(STATS_NETWORK_SUCCESS)
                || key.equals(STATS_NETWORK_FAILURE)
                || key.equals(STATS_ERROR)
                || key.equals(STATS_WARN);
    }

    @Override
    public void eventReceived(Event event) {
        String site;
        HistoryReference href = event.getTarget().getStartNode().getHistoryReference();
        if (href.getHistoryType() == HistoryReference.TYPE_TEMPORARY) {
            return;
        }
        try {
            site = SessionStructure.getHostName(href.getURI());
            stats.counterInc(site, INSIGHTS_ENDPOINTS_TOTAL);
            stats.counterInc(site, INSIGHTS_ENDPOINTS_METHOD_PREFIX + href.getMethod());

            Map<String, String> params = event.getParameters();
            if (params != null && params.containsKey("contentType")) {
                String ct = params.get("contentType");
                int semicolonIdx = ct.indexOf(';');
                if (semicolonIdx > 0) {
                    ct = ct.substring(0, semicolonIdx);
                }
                stats.counterInc(site, INSIGHTS_ENDPOINTS_CTYPE_PREFIX + ct);
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
