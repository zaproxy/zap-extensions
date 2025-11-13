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
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.insights.ExtensionInsights;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.utils.StatsListener;

public class StatsMonitor implements StatsListener {

    private static final String STATS_CODE_PREFIX = "stats.code.";
    private static final String STATS_ERROR = "stats.log.error";
    private static final String STATS_WARN = "stats.log.warn";
    private static final String STATS_NETWORK_FAILURE = "stats.network.send.failure";
    private static final String STATS_NETWORK_SUCCESS = "stats.network.send.success";

    private static final int MIN_NUMBER_OF_REQS = 1000;

    private InMemoryStats stats = new InMemoryStats();

    private ExtensionInsights ext;

    public StatsMonitor(ExtensionInsights extensionInsights) {
        this.ext = extensionInsights;
    }

    public InMemoryStats getCachedStats() {
        return stats;
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

            if (tot400 > total / 20) {
                recordInsight(
                        Insight.Level.Low, site, STATS_CODE_PREFIX + "4xx", tot400 * 100 / total);
            }
            if (tot500 > total / 20) {
                recordInsight(
                        Insight.Level.Low, site, STATS_CODE_PREFIX + "5xx", tot500 * 100 / total);
            }
        }

        // Network problems
        long netGood = unbox(stats.getStat(STATS_NETWORK_SUCCESS));
        long netBad = unbox(stats.getStat(STATS_NETWORK_FAILURE));
        long netTotal = netGood + netBad;
        if (netTotal > MIN_NUMBER_OF_REQS) {
            if (netBad > netTotal / 2) {
                recordInsight(
                        Insight.Level.High, "stats.network.failure.high", netBad * 100 / netTotal);
            }
            if (netBad > netTotal / 20) {
                recordInsight(
                        Insight.Level.Medium,
                        "stats.network.failure.medium",
                        netBad * 100 / netTotal);
            }
        }

        // ZAP errors and warnings
        recordNonZeroInsight(Insight.Level.Low, STATS_ERROR);
        recordNonZeroInsight(Insight.Level.Low, STATS_WARN);
    }

    private boolean isRelevant(String key) {
        if (key.startsWith(STATS_CODE_PREFIX)
                || key.equals(STATS_ERROR)
                || key.equals(STATS_WARN)) {
            return true;
        }
        return false;
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
