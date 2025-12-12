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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
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
    private List<InsightListener> listenners = Collections.synchronizedList(new ArrayList<>());

    private boolean disableExit;

    public ExtensionInsights() {
        super(NAME);
        setI18nPrefix(PREFIX);

        statsMonitor = new StatsMonitor(this);
        insights = new Insights();
        this.addInsightListener(insights);

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
            this.addInsightListener(insightsPanel);
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

    public void addInsightListener(InsightListener listener) {
        this.listenners.add(listener);
    }

    public void removeInsightListener(InsightListener listener) {
        this.listenners.remove(listener);
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
        this.listenners.forEach(il -> il.recordInsight(ins));

        if (!hasView()
                && this.getParam().isExitAutoOnHigh()
                && !this.isDisableExit()
                && ins.getLevel().equals(Insight.Level.HIGH)) {
            Control control = Control.getSingleton();
            control.setExitStatus(2, "Shutting down ZAP due to High Level Insight");
            control.exit(false, null);
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

    /**
     * Returns whether the option to automatically exit on a High insight has been disabled.
     *
     * @return
     */
    public boolean isDisableExit() {
        return disableExit;
    }

    /**
     * If set to true then the extension will not automatically exit on a High insight, even if
     * configured to do so. The caller is essentially taking responsibility for handling the High
     * insight.
     *
     * @param disableExit
     */
    public void setDisableExit(boolean disableExit) {
        this.disableExit = disableExit;
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
