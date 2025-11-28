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
package org.zaproxy.addon.insights;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.SiteMapEventPublisher;
import org.zaproxy.addon.insights.internal.Insight;
import org.zaproxy.addon.insights.internal.Insights;
import org.zaproxy.addon.insights.internal.InsightsPanel;
import org.zaproxy.addon.insights.internal.InsightsParam;
import org.zaproxy.addon.insights.internal.OptionsPanel;
import org.zaproxy.addon.insights.internal.StatsMonitor;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.utils.Stats;

public class ExtensionInsights extends ExtensionAdaptor {

    public static final String NAME = "ExtensionInsights";

    public static final String PREFIX = "insights";

    private static final String RESOURCES = "resources/";

    private InsightsPanel insightsPanel;
    private StatsMonitor statsMonitor;
    private PollThread pollThread;
    private Insights insights;
    private InsightsParam param;

    private boolean haveSwitched;

    public ExtensionInsights() {
        super(NAME);
        setI18nPrefix(PREFIX);

        statsMonitor = new StatsMonitor(this);
        insights = new Insights();
        Stats.addListener(statsMonitor);

        ZAP.getEventBus()
                .registerConsumer(
                        statsMonitor,
                        SiteMapEventPublisher.class.getCanonicalName(),
                        SiteMapEventPublisher.SITE_NODE_ADDED_EVENT);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extensionHook.addOptionsParamSet(getParam());

        if (hasView()) {
            insightsPanel = new InsightsPanel();
            extensionHook.getHookView().addStatusPanel(insightsPanel);
            extensionHook.getHookView().addOptionPanel(new OptionsPanel());
        }
    }

    public InsightsParam getParam() {
        if (param == null) {
            param = new InsightsParam();
        }
        return param;
    }

    public StatsMonitor getStatsMonitor() {
        return statsMonitor;
    }

    @Override
    public void optionsLoaded() {
        pollThread = new PollThread();
        pollThread.start();

        if (insightsPanel != null) {
            insightsPanel.setInsights(insights.getInsightList());
        }
    }

    public void recordInsight(Insight ins) {
        insights.recordInsight(ins);
        if (insightsPanel != null) {
            insightsPanel.pack();
            if (Insight.Level.HIGH.equals(ins.getLevel()) && !haveSwitched) {
                insightsPanel.setTabFocus();
                haveSwitched = true;
            }
        }
    }

    public List<Insight> getInsights() {
        return this.insights.getInsightList();
    }

    public Map<String, Map<String, Insight>> getInsightMap() {
        return this.insights.getInsightMap();
    }

    public void processStats() {
        if (statsMonitor != null) {
            this.statsMonitor.processStats();
        }
    }

    public void clearInsights() {
        this.insights.clear();
        // This will indicate the insights have changed
        if (insightsPanel != null) {
            insightsPanel.setInsights(insights.getInsightList());
            insights.setModel(insightsPanel.getModel());
        }
    }

    public static URL getResource(String resource) {
        return ExtensionInsights.class.getResource(ExtensionInsights.RESOURCES + resource);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        this.stop();
        if (statsMonitor != null) {
            Stats.removeListener(statsMonitor);
        }
        ZAP.getEventBus().unregisterConsumer(statsMonitor);
    }

    @Override
    public void stop() {
        if (pollThread != null) {
            pollThread.stopThread();
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    private class PollThread extends Thread {

        private boolean stop;

        public PollThread() {
            super("ZAP-Insights");
        }

        public void stopThread() {
            stop = true;
            this.interrupt();
        }

        @Override
        public void run() {
            while (!stop) {
                statsMonitor.processStats();
                try {
                    sleep(TimeUnit.SECONDS.toMillis(5));
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
        }
    }
}
