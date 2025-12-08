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

import org.zaproxy.zap.common.VersionedAbstractParam;

public class InsightsParam extends VersionedAbstractParam {

    private static final String INSIGHTS_KEY = "insights";

    private static final String CONFIG_VERSION_KEY = INSIGHTS_KEY + VERSION_ATTRIBUTE;
    public static final String MSG_LOW_THRESHOLD_KEY = INSIGHTS_KEY + ".msgLow";
    public static final String MSG_HIGH_THRESHOLD_KEY = INSIGHTS_KEY + ".msgHigh";
    public static final String MEM_LOW_THRESHOLD_KEY = INSIGHTS_KEY + ".memLow";
    public static final String MEM_HIGH_THRESHOLD_KEY = INSIGHTS_KEY + ".memHigh";
    public static final String SLOW_RESPONSE_KEY = INSIGHTS_KEY + ".slow";
    public static final String EXIT_AUTO_KEY = INSIGHTS_KEY + ".exitAuto";

    public static final int DEFAULT_MSG_LOW_THRESHOLD = 5;
    public static final int DEFAULT_MSG_HIGH_THRESHOLD = 50;
    public static final int DEFAULT_MEM_LOW_THRESHOLD = 80;
    public static final int DEFAULT_MEM_HIGH_THRESHOLD = 95;
    public static final int DEFAULT_SLOW_RESPONSE = 256;
    public static final boolean DEFAULT_EXIT_AUTO_ON_HIGH = true;

    private int messagesLowThreshold = DEFAULT_MSG_LOW_THRESHOLD;
    private int messagesHighThreshold = DEFAULT_MSG_HIGH_THRESHOLD;
    private int memoryLowThreshold = DEFAULT_MEM_LOW_THRESHOLD;
    private int memoryHighThreshold = DEFAULT_MEM_HIGH_THRESHOLD;
    private int slowResponse = DEFAULT_SLOW_RESPONSE;
    private boolean exitAutoOnHigh = DEFAULT_EXIT_AUTO_ON_HIGH;

    protected static final int CURRENT_CONFIG_VERSION = 1;

    public InsightsParam() {}

    @Override
    protected void parseImpl() {
        this.messagesLowThreshold = this.getInt(MSG_LOW_THRESHOLD_KEY, DEFAULT_MSG_LOW_THRESHOLD);
        this.messagesHighThreshold =
                this.getInt(MSG_HIGH_THRESHOLD_KEY, DEFAULT_MSG_HIGH_THRESHOLD);
        this.memoryLowThreshold = this.getInt(MEM_LOW_THRESHOLD_KEY, DEFAULT_MEM_LOW_THRESHOLD);
        this.memoryHighThreshold = this.getInt(MEM_HIGH_THRESHOLD_KEY, DEFAULT_MEM_HIGH_THRESHOLD);
        this.slowResponse = nextPowerOfTwo(this.getInt(SLOW_RESPONSE_KEY, DEFAULT_SLOW_RESPONSE));
        this.exitAutoOnHigh = this.getBoolean(EXIT_AUTO_KEY, true);
    }

    public int getMessagesLowThreshold() {
        return messagesLowThreshold;
    }

    public void setMessagesLowThreshold(int messagesLowThreshold) {
        this.messagesLowThreshold = messagesLowThreshold;
        getConfig().setProperty(MSG_LOW_THRESHOLD_KEY, messagesLowThreshold);
    }

    public int getMessagesHighThreshold() {
        return messagesHighThreshold;
    }

    public void setMessagesHighThreshold(int messagesHighThreshold) {
        this.messagesHighThreshold = messagesHighThreshold;
        getConfig().setProperty(MSG_HIGH_THRESHOLD_KEY, messagesHighThreshold);
    }

    public int getMemoryLowThreshold() {
        return memoryLowThreshold;
    }

    public void setMemoryLowThreshold(int memoryLowThreshold) {
        this.memoryLowThreshold = memoryLowThreshold;
        getConfig().setProperty(MEM_LOW_THRESHOLD_KEY, memoryLowThreshold);
    }

    public int getMemoryHighThreshold() {
        return memoryHighThreshold;
    }

    public void setMemoryHighThreshold(int memoryHighThreshold) {
        this.memoryHighThreshold = memoryHighThreshold;
        getConfig().setProperty(MEM_HIGH_THRESHOLD_KEY, memoryHighThreshold);
    }

    public int getSlowResponse() {
        return nextPowerOfTwo(slowResponse);
    }

    public void setSlowResponse(int slowResponse) {
        this.slowResponse = nextPowerOfTwo(slowResponse);
        getConfig().setProperty(SLOW_RESPONSE_KEY, this.slowResponse);
    }

    private static int nextPowerOfTwo(int x) {
        if (x <= 1) return 1;

        int h = Integer.highestOneBit(x);
        return (h == x) ? x : h << 1;
    }

    public boolean isExitAutoOnHigh() {
        return exitAutoOnHigh;
    }

    public void setExitAutoOnHigh(boolean exitAutoOnHigh) {
        this.exitAutoOnHigh = exitAutoOnHigh;
        getConfig().setProperty(EXIT_AUTO_KEY, this.exitAutoOnHigh);
    }

    @Override
    protected String getConfigVersionKey() {
        return CONFIG_VERSION_KEY;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // Currently nothing to do
    }
}
