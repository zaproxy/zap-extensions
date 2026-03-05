/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.mcp;

import java.security.SecureRandom;
import org.zaproxy.zap.common.VersionedAbstractParam;

/** MCP add-on parameters. */
public class McpParam extends VersionedAbstractParam {

    private static final String MCP_KEY = "mcp";

    private static final String CONFIG_VERSION_KEY = MCP_KEY + VERSION_ATTRIBUTE;
    private static final String PORT_KEY = MCP_KEY + ".port";
    private static final String SECURITY_KEY_ENABLED_KEY = MCP_KEY + ".securityKeyEnabled";
    private static final String SECURITY_KEY_KEY = MCP_KEY + ".securityKey";
    private static final String RECORD_IN_HISTORY_KEY = MCP_KEY + ".recordInHistory";

    private static final int CURRENT_CONFIG_VERSION = 1;

    private static final int SECURITY_KEY_LENGTH = 32;

    /** Default port for the MCP HTTP listener. */
    public static final int DEFAULT_PORT = 8282;

    private int port = DEFAULT_PORT;
    private boolean securityKeyEnabled = true;
    private String securityKey;
    private boolean recordInHistory = false;

    public McpParam() {}

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
        // Nothing to migrate
    }

    @Override
    protected void parseImpl() {
        port = getInt(PORT_KEY, DEFAULT_PORT);
        securityKeyEnabled = getBoolean(SECURITY_KEY_ENABLED_KEY, true);
        securityKey = getString(SECURITY_KEY_KEY, null);
        recordInHistory = getBoolean(RECORD_IN_HISTORY_KEY, false);
        if (securityKey == null || securityKey.isBlank()) {
            securityKey = generateRandomKey();
            getConfig().setProperty(SECURITY_KEY_KEY, securityKey);
        }
    }

    private static String generateRandomKey() {
        return generateRandomKeyForUi();
    }

    /** Generates a random key for use in the UI or config. */
    public static String generateRandomKeyForUi() {
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder(SECURITY_KEY_LENGTH);
        for (int i = 0; i < SECURITY_KEY_LENGTH; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
        getConfig().setProperty(PORT_KEY, port);
    }

    public boolean isSecurityKeyEnabled() {
        return securityKeyEnabled;
    }

    public void setSecurityKeyEnabled(boolean enabled) {
        this.securityKeyEnabled = enabled;
        getConfig().setProperty(SECURITY_KEY_ENABLED_KEY, enabled);
    }

    public String getSecurityKey() {
        return securityKey;
    }

    public void setSecurityKey(String key) {
        this.securityKey = key != null ? key : "";
        getConfig().setProperty(SECURITY_KEY_KEY, this.securityKey);
    }

    /** Returns the required security key when enabled, or null when disabled. */
    public String getRequiredSecurityKey() {
        return securityKeyEnabled && securityKey != null && !securityKey.isBlank()
                ? securityKey
                : null;
    }

    /** Returns whether MCP server requests should be recorded in ZAP history. */
    public boolean isRecordInHistory() {
        return recordInHistory;
    }

    /** Sets whether MCP server requests should be recorded in ZAP history. */
    public void setRecordInHistory(boolean enabled) {
        this.recordInHistory = enabled;
        getConfig().setProperty(RECORD_IN_HISTORY_KEY, enabled);
    }
}
