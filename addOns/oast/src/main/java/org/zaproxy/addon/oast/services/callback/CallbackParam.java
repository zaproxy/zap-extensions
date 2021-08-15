/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast.services.callback;

import java.util.List;
import org.zaproxy.zap.common.VersionedAbstractParam;
import org.zaproxy.zap.utils.NetworkUtils;

/** @author psiinon */
public class CallbackParam extends VersionedAbstractParam {

    private static final int PARAM_CURRENT_VERSION = 1;

    private static final String PROXY_BASE_KEY = "oast.callback";

    private static final String LOCAL_ADDRESS_KEY = PROXY_BASE_KEY + ".localaddr";
    private static final String REMOTE_ADDRESS_KEY = PROXY_BASE_KEY + ".remoteaddr";
    private static final String PORT_KEY = PROXY_BASE_KEY + ".port";

    private static final String SECURE_KEY = PROXY_BASE_KEY + ".secure";

    private String localAddress;
    private String remoteAddress;
    private int port;
    private boolean secure;

    @Override
    protected void parseImpl() {
        localAddress = getString(LOCAL_ADDRESS_KEY, "0.0.0.0");
        remoteAddress = getString(REMOTE_ADDRESS_KEY, getDefaultAddress());
        port = getInt(PORT_KEY, 0);
        secure = getBoolean(SECURE_KEY, false);
    }

    @Override
    protected String getConfigVersionKey() {
        return PROXY_BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return PARAM_CURRENT_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    private String getDefaultAddress() {
        List<String> addrs = NetworkUtils.getAvailableAddresses(false);
        for (String addr : addrs) {
            if (!addr.contains(":") && !addr.equals("localhost") && !addr.equals("127.0.0.1")) {
                // Return the first IPv4 one that's not localhost
                return addr;
            }
        }
        if (!addrs.isEmpty()) {
            return addrs.get(0);
        }
        // Better than nothing
        return "localhost";
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(String localAddress) {
        if (this.localAddress.equals(localAddress)) {
            return;
        }
        this.localAddress = localAddress.trim();
        getConfig().setProperty(LOCAL_ADDRESS_KEY, this.localAddress);
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public void setRemoteAddress(String remoteAddress) {
        if (this.remoteAddress.equals(remoteAddress)) {
            return;
        }
        this.remoteAddress = remoteAddress.trim();
        getConfig().setProperty(REMOTE_ADDRESS_KEY, this.remoteAddress);
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        if (this.port == port) {
            return;
        }
        this.port = port;
        getConfig().setProperty(PORT_KEY, Integer.toString(this.port));
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        if (this.secure == secure) {
            return;
        }
        this.secure = secure;
        getConfig().setProperty(SECURE_KEY, Boolean.toString(this.secure));
    }
}
