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

import java.util.Locale;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.parosproxy.paros.Constant;

@Getter
@AllArgsConstructor
public class Insight {

    public enum Level {
        HIGH,
        MEDIUM,
        LOW,
        INFO;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "insights.table.level." + this.name().toLowerCase(Locale.ROOT));
        }
    }

    public enum Reason {
        INFO,
        WARNING,
        EXCEEDED_LOW,
        EXCEEDED_HIGH;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "insights.table.reason." + this.name().toLowerCase(Locale.ROOT));
        }
    }

    private Level level;
    private Reason reason;
    private String site;
    private String key;
    private String description;
    private long statistic;
    private boolean percent;

    public Insight(String site, String key, String description, long statistic) {
        this(Level.INFO, Reason.INFO, site, key, description, statistic, false);
    }

    public Insight(String site, String key, String description, long statistic, boolean percent) {
        this(Level.INFO, Reason.INFO, site, key, description, statistic, percent);
    }

    public String getStatisticStr() {
        return isPercent()
                ? Constant.messages.getString("insights.insight.statistic.percent", getStatistic())
                : Constant.messages.getString("insights.insight.statistic.plain", getStatistic());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (o instanceof Insight ins) {
            return level == ins.level
                    && reason == ins.reason
                    && Objects.equals(site, ins.site)
                    && Objects.equals(key, ins.key)
                    && Objects.equals(statistic, ins.statistic);
        }
        return false;
    }

    @Override
    public String toString() {
        return "Insight: "
                + level.name()
                + " : "
                + reason.name()
                + " : "
                + site
                + " : "
                + key
                + " : "
                + statistic;
    }

    @Override
    public int hashCode() {
        return Objects.hash(level, site, key, statistic);
    }
}
