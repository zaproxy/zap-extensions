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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.zaproxy.addon.insights.InsightListener;
import org.zaproxy.zap.utils.ThreadUtils;

public class Insights implements InsightListener {

    private Map<String, Map<String, Insight>> insightMap;
    private List<Insight> insightList;
    private InsightsTableModel model;

    private static final Comparator<Insight> INSIGHT_COMPARATOR =
            Comparator.comparing(Insight::getLevel)
                    .thenComparing(Comparator.comparing(Insight::getSite))
                    .thenComparing(Comparator.comparing(Insight::getKey));

    public Insights() {
        clear();
    }

    public void clear() {
        insightMap = new HashMap<>();
        insightList = Collections.synchronizedList(new ArrayList<>());
    }

    public List<Insight> getInsightList() {
        return insightList;
    }

    public Map<String, Map<String, Insight>> getInsightMap() {
        return insightMap;
    }

    public void setModel(InsightsTableModel model) {
        this.model = model;
    }

    @Override
    public void recordInsight(Insight insight) {
        Map<String, Insight> siteInsights =
                insightMap.computeIfAbsent(
                        insight.getSite(), k -> Collections.synchronizedMap(new HashMap<>()));

        Insight oldInsight = siteInsights.get(insight.getKey());

        if (oldInsight == null || oldInsight.getLevel().ordinal() >= insight.getLevel().ordinal()) {
            if (insight.equals(oldInsight)) {
                return;
            }
            siteInsights.put(insight.getKey(), insight);

            if (oldInsight != null) {
                this.insightList.remove(oldInsight);
            }
            this.insightList.add(insight);
            this.insightList.sort(INSIGHT_COMPARATOR);
            int index = this.insightList.indexOf(insight);
            if (model != null) {
                final int indexFinal = index;
                final boolean addedFinal = oldInsight == null;
                ThreadUtils.invokeLater(() -> model.insightChanged(indexFinal, addedFinal));
            }
        }
    }
}
