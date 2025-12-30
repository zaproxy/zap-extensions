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
package org.zaproxy.addon.llm;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class LlmOptions extends VersionedAbstractParam {

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     *
     * <p>It only needs to be updated for configurations changes (not releases of the add-on).
     */
    private static final int CURRENT_VERSION = 1;

    private static final String BASE_KEY = "llm";

    public static final String MODEL_PROVIDER_PROPERTY = BASE_KEY + ".modelprovider";
    public static final String APIKEY_PROPERTY = BASE_KEY + ".apikey";
    public static final String ENDPOINT_PROPERTY = BASE_KEY + ".endpoint";
    public static final String MODEL_NAME_PROPERTY = BASE_KEY + ".modelname";

    private LlmProvider modelProvider = LlmProvider.NONE;

    private String apiKey;

    private String endpoint;

    private String modelName;

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_VERSION;
    }

    @Override
    protected void parseImpl() {
        modelProvider = getEnum(MODEL_PROVIDER_PROPERTY, LlmProvider.NONE);
        apiKey = getString(APIKEY_PROPERTY, "");
        endpoint = getString(ENDPOINT_PROPERTY, "");
        modelName = getString(MODEL_NAME_PROPERTY, "");
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
        getConfig().setProperty(APIKEY_PROPERTY, this.apiKey);
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
        getConfig().setProperty(ENDPOINT_PROPERTY, this.endpoint);
    }

    public String getModelName() {
        return modelName;
    }

    public void setModelName(String modelName) {
        this.modelName = modelName;
        getConfig().setProperty(MODEL_NAME_PROPERTY, this.modelName);
    }

    public LlmProvider getModelProvider() {
        return modelProvider;
    }

    public void setModelProvider(LlmProvider modelProvider) {
        this.modelProvider = modelProvider;
        getConfig().setProperty(MODEL_PROVIDER_PROPERTY, this.modelProvider.name());
    }

    public boolean hasCommsChanged(LlmOptions options) {
        return !this.modelProvider.equals(options.modelProvider)
                || !Strings.CS.equals(this.endpoint, options.endpoint)
                || !Strings.CS.equals(this.apiKey, options.apiKey)
                || !Strings.CS.equals(this.modelName, options.modelName);
    }

    public boolean isCommsConfigured() {
        return !LlmProvider.NONE.equals(this.modelProvider) && !StringUtils.isBlank(endpoint);
    }

    public String getCommsIssue() {
        if (LlmProvider.NONE.equals(this.modelProvider)) {
            return Constant.messages.getString("llm.error.provider");
        }
        if (StringUtils.isBlank(endpoint)) {
            return Constant.messages.getString("llm.error.endpoint");
        }
        return null;
    }
}
