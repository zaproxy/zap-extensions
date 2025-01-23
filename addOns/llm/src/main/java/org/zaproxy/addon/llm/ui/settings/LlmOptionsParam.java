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
package org.zaproxy.addon.llm.ui.settings;

import org.zaproxy.zap.common.VersionedAbstractParam;

public class LlmOptionsParam extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    /** The base configuration key for all "llm" configurations. */
    private static final String BASE_KEY = "llm";

    public static final String APIKEY_PROPERTY = BASE_KEY + ".apikey";
    public static final String ENDPOINT_PROPERTY = BASE_KEY + ".endpoint";

    public static final String MODEL_NAME_PROPERTY = BASE_KEY + ".modelname";

    /** The API key */
    private String apiKey;

    /** The Endpoint */
    private String endpoint;

    /** The model name */
    private String modelName;

    public LlmOptionsParam() {}

    public String getApiKey() {
        return this.apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
        getConfig().setProperty(APIKEY_PROPERTY, this.apiKey);
    }

    public String getEndpoint() {
        return this.endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
        getConfig().setProperty(ENDPOINT_PROPERTY, this.endpoint);
    }

    public String getModelName() {
        return this.modelName;
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
        getConfig().setProperty(MODEL_NAME_PROPERTY, this.modelName);
    }

    @Override
    protected void parseImpl() {
        this.apiKey = this.getString(APIKEY_PROPERTY, "");
        this.endpoint = this.getString(ENDPOINT_PROPERTY, "");
        this.modelName = this.getString(MODEL_NAME_PROPERTY, "");
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}
}
