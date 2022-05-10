/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network;

import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.httpclient.HttpState;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.ConnectionParam;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class LegacyConnectionParam extends ConnectionParam {

    private final ConnectionParam connectionOptions;

    LegacyConnectionParam() {
        this.connectionOptions = Model.getSingleton().getOptionsParam().getConnectionParam();
        super.load(new ZapXmlConfiguration());
    }

    @Override
    public void load(FileConfiguration config) {
        // Nothing to do.
    }

    @Override
    protected void parse() {
        // Nothing to do.
    }

    @Override
    public String getDefaultUserAgent() {
        return connectionOptions.getDefaultUserAgent();
    }

    @Override
    public void setDefaultUserAgent(String defaultUserAgent) {
        connectionOptions.setDefaultUserAgent(defaultUserAgent);
    }

    @Override
    public int getDnsTtlSuccessfulQueries() {
        return connectionOptions.getDnsTtlSuccessfulQueries();
    }

    @Override
    public void setDnsTtlSuccessfulQueries(int ttl) {
        connectionOptions.setDnsTtlSuccessfulQueries(ttl);
    }

    @Override
    public HttpState getHttpState() {
        return connectionOptions.getHttpState();
    }

    @Override
    public boolean isHttpStateEnabled() {
        return connectionOptions.isHttpStateEnabled();
    }

    @Override
    public void setHttpStateEnabled(boolean httpStateEnabled) {
        connectionOptions.setHttpStateEnabled(httpStateEnabled);
    }

    @Override
    public String getProxyChainName() {
        return connectionOptions.getProxyChainUserName();
    }

    @Override
    public void setProxyChainName(String proxyChainName) {
        connectionOptions.setProxyChainName(proxyChainName);
    }

    @Override
    public String getProxyChainPassword() {
        return connectionOptions.getProxyChainPassword();
    }

    @Override
    public void setProxyChainPassword(String proxyChainPassword) {
        connectionOptions.setProxyChainPassword(proxyChainPassword);
    }

    @Override
    public int getProxyChainPort() {
        return connectionOptions.getProxyChainPort();
    }

    @Override
    public void setProxyChainPort(int proxyChainPort) {
        connectionOptions.setProxyChainPort(proxyChainPort);
    }

    @Override
    public boolean isProxyChainPrompt() {
        return connectionOptions.isProxyChainPrompt();
    }

    @Override
    public void setProxyChainPrompt(boolean proxyPrompt) {
        connectionOptions.setProxyChainPrompt(proxyPrompt);
    }

    @Override
    public String getProxyChainRealm() {
        return connectionOptions.getProxyChainRealm();
    }

    @Override
    public void setProxyChainRealm(String proxyChainRealm) {
        connectionOptions.setProxyChainRealm(proxyChainRealm);
    }

    @Override
    public String getProxyChainUserName() {
        return connectionOptions.getProxyChainUserName();
    }

    @Override
    public void setProxyChainUserName(String proxyChainUserName) {
        connectionOptions.setProxyChainUserName(proxyChainUserName);
    }

    @Override
    @Deprecated
    public boolean isSingleCookieRequestHeader() {
        return true;
    }

    @Override
    @Deprecated
    public void setSingleCookieRequestHeader(boolean singleCookieRequestHeader) {
        // Nothing to do, the opiton is always enabled.
    }

    @Override
    public int getTimeoutInSecs() {
        return connectionOptions.getTimeoutInSecs();
    }

    @Override
    public void setTimeoutInSecs(int timeoutInSecs) {
        connectionOptions.setTimeoutInSecs(timeoutInSecs);
    }

    @Override
    public boolean isUseProxyChain() {
        return connectionOptions.isUseProxyChain();
    }

    @Override
    public void setUseProxyChain(boolean useProxyChain) {
        connectionOptions.setUseProxyChain(useProxyChain);
    }

    @Override
    public boolean isUseProxyChainAuth() {
        return connectionOptions.isUseProxyChainAuth();
    }

    @Override
    public void setUseProxyChainAuth(boolean useProxyChainAuth) {
        connectionOptions.setUseProxyChainAuth(useProxyChainAuth);
    }

    @Override
    public boolean isUseSocksProxy() {
        return connectionOptions.isUseSocksProxy();
    }

    @Override
    public void setUseSocksProxy(boolean useSocksProxy) {
        connectionOptions.setUseSocksProxy(useSocksProxy);
    }

    @Override
    @ZapApiIgnore
    public boolean shouldResolveRemoteHostname(String hostname) {
        return connectionOptions.shouldResolveRemoteHostname(hostname);
    }
}
