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
package org.zaproxy.zap.extension.llmheader;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class LLMHeaderOptions extends VersionedAbstractParam {

    private static final int VERSION = 1;

    private static final String ENABLED = "llmheader.enabled";
    private static final String ANONYMIZE = "llmheader.anonymize";
    private static final String MODE = "llmheader.mode";
    private static final String SAMPLING_RATE = "llmheader.sampling";
    private static final String BRIDGE_URL = "llmheader.bridgeUrl";
    private static final String GEMINI_KEY = "llmheader.geminiKey";
    private static final String GEMINI_MODEL = "llmheader.geminiModel";
    private static final String AUTO_ALERT = "llmheader.autoAlert";

    public static final int MODE_MANUAL = 0;
    public static final int MODE_AUTO_SAMPLE = 1;
    public static final int MODE_AUTO_ALL = 2;

    private boolean enabled;
    private boolean anonymize;
    private int mode;
    private int samplingRate;
    private int rateLimit;
    private String bridgeUrl;
    private String geminiKey;
    private String geminiModel;
    private boolean autoAlert;

    @Override
    protected void parseImpl() {
        enabled = getBoolean(ENABLED, true); // Default TRUE
        anonymize = getBoolean(ANONYMIZE, true);
        mode = getInt(MODE, MODE_AUTO_ALL); // Default ALL
        samplingRate = getInt(SAMPLING_RATE, 10);
        rateLimit = getInt("llmheader.ratelimit", 60);
        bridgeUrl = getString(BRIDGE_URL, "");
        geminiKey = getString(GEMINI_KEY, "");
        geminiModel = getString(GEMINI_MODEL, "gemini-2.5-flash");
        autoAlert = getBoolean(AUTO_ALERT, true); // Default TRUE
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {
        // No updates needed for version 1
    }

    @Override
    protected int getCurrentVersion() {
        return VERSION;
    }

    @Override
    protected String getConfigVersionKey() {
        return "llmheader.version";
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        getConfig().setProperty(ENABLED, enabled);
    }

    public boolean isAnonymize() {
        return anonymize;
    }

    public void setAnonymize(boolean anonymize) {
        this.anonymize = anonymize;
        getConfig().setProperty(ANONYMIZE, anonymize);
    }

    public int getMode() {
        return mode;
    }

    public void setMode(int mode) {
        this.mode = mode;
        getConfig().setProperty(MODE, mode);
    }

    public int getSamplingRate() {
        return samplingRate;
    }

    public void setSamplingRate(int samplingRate) {
        this.samplingRate = samplingRate;
        getConfig().setProperty(SAMPLING_RATE, samplingRate);
    }

    public int getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(int rateLimit) {
        this.rateLimit = rateLimit;
        getConfig().setProperty("llmheader.ratelimit", rateLimit);
    }

    public String getBridgeUrl() {
        return bridgeUrl;
    }

    public void setBridgeUrl(String bridgeUrl) {
        this.bridgeUrl = bridgeUrl;
        getConfig().setProperty(BRIDGE_URL, bridgeUrl);
    }

    public String getGeminiKey() {
        return geminiKey;
    }

    public void setGeminiKey(String geminiKey) {
        this.geminiKey = geminiKey;
        getConfig().setProperty(GEMINI_KEY, geminiKey);
    }

    public String getGeminiModel() {
        return geminiModel;
    }

    public void setGeminiModel(String geminiModel) {
        this.geminiModel = geminiModel;
        getConfig().setProperty(GEMINI_MODEL, geminiModel);
    }

    public boolean isAutoAlert() {
        return autoAlert;
    }

    public void setAutoAlert(boolean autoAlert) {
        this.autoAlert = autoAlert;
        getConfig().setProperty(AUTO_ALERT, autoAlert);
    }
}
