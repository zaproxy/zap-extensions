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

import java.net.PasswordAuthentication;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.commons.httpclient.HttpState;
import org.parosproxy.paros.network.ConnectionParam;
import org.zaproxy.addon.network.internal.client.HttpProxy;
import org.zaproxy.addon.network.internal.client.HttpProxyExclusion;
import org.zaproxy.zap.extension.api.ZapApiIgnore;
import org.zaproxy.zap.network.DomainMatcher;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class LegacyConnectionParam extends ConnectionParam {

    private final Supplier<HttpState> httpStateSupplier;
    private final ConnectionOptions connectionOptions;

    LegacyConnectionParam(
            Supplier<HttpState> httpStateSupplier, ConnectionOptions connectionOptions) {
        this.httpStateSupplier = httpStateSupplier;
        this.connectionOptions = connectionOptions;
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
        return httpStateSupplier.get();
    }

    @Override
    public void setHttpState(HttpState httpState) {
        // Nothing to do, state is now kept in the extension.
    }

    @Override
    public boolean isHttpStateEnabled() {
        return connectionOptions.isUseGlobalHttpState();
    }

    @Override
    public void setHttpStateEnabled(boolean httpStateEnabled) {
        connectionOptions.setUseGlobalHttpState(httpStateEnabled);
    }

    @Override
    public String getProxyChainName() {
        return connectionOptions.getHttpProxy().getHost();
    }

    @Override
    public void setProxyChainName(String proxyChainName) {
        HttpProxy oldProxy = connectionOptions.getHttpProxy();
        HttpProxy httpProxy =
                new HttpProxy(
                        proxyChainName,
                        oldProxy.getPort(),
                        oldProxy.getRealm(),
                        oldProxy.getPasswordAuthentication());
        connectionOptions.setHttpProxy(httpProxy);
    }

    @Override
    public String getProxyChainPassword() {
        return new String(
                connectionOptions.getHttpProxy().getPasswordAuthentication().getPassword());
    }

    @Override
    public void setProxyChainPassword(String proxyChainPassword) {
        HttpProxy oldProxy = connectionOptions.getHttpProxy();
        HttpProxy httpProxy =
                new HttpProxy(
                        oldProxy.getHost(),
                        oldProxy.getPort(),
                        oldProxy.getRealm(),
                        new PasswordAuthentication(
                                oldProxy.getPasswordAuthentication().getUserName(),
                                proxyChainPassword.toCharArray()));
        connectionOptions.setHttpProxy(httpProxy);
    }

    @Override
    @Deprecated
    public void setProxyChainSkipName(String proxyChainSkipName) {
        // Overridden to expose in the ZAP API.
        super.setProxyChainSkipName(proxyChainSkipName);
    }

    @Override
    public int getProxyChainPort() {
        return connectionOptions.getHttpProxy().getPort();
    }

    @Override
    public void setProxyChainPort(int proxyChainPort) {
        HttpProxy oldProxy = connectionOptions.getHttpProxy();
        HttpProxy httpProxy =
                new HttpProxy(
                        oldProxy.getHost(),
                        proxyChainPort,
                        oldProxy.getRealm(),
                        oldProxy.getPasswordAuthentication());
        connectionOptions.setHttpProxy(httpProxy);
    }

    @Override
    public boolean isProxyChainPrompt() {
        return !connectionOptions.isStoreHttpProxyPass();
    }

    @Override
    public void setProxyChainPrompt(boolean proxyPrompt) {
        connectionOptions.setStoreHttpProxyPass(!proxyPrompt);
    }

    @Override
    public String getProxyChainRealm() {
        return connectionOptions.getHttpProxy().getRealm();
    }

    @Override
    public void setProxyChainRealm(String proxyChainRealm) {
        HttpProxy oldProxy = connectionOptions.getHttpProxy();
        HttpProxy httpProxy =
                new HttpProxy(
                        oldProxy.getHost(),
                        oldProxy.getPort(),
                        proxyChainRealm,
                        oldProxy.getPasswordAuthentication());
        connectionOptions.setHttpProxy(httpProxy);
    }

    @Override
    public String getProxyChainUserName() {
        return connectionOptions.getHttpProxy().getPasswordAuthentication().getUserName();
    }

    @Override
    public void setProxyChainUserName(String proxyChainUserName) {
        HttpProxy oldProxy = connectionOptions.getHttpProxy();
        HttpProxy httpProxy =
                new HttpProxy(
                        oldProxy.getHost(),
                        oldProxy.getPort(),
                        oldProxy.getRealm(),
                        new PasswordAuthentication(
                                proxyChainUserName,
                                oldProxy.getPasswordAuthentication().getPassword()));
        connectionOptions.setHttpProxy(httpProxy);
    }

    @Override
    @Deprecated
    public boolean isSingleCookieRequestHeader() {
        return true;
    }

    @Override
    @Deprecated
    public void setSingleCookieRequestHeader(boolean singleCookieRequestHeader) {
        // Nothing to do, the option is always enabled.
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
        return connectionOptions.isHttpProxyEnabled();
    }

    @Override
    public void setUseProxyChain(boolean useProxyChain) {
        connectionOptions.setHttpProxyEnabled(useProxyChain);
    }

    @Override
    public boolean isUseProxyChainAuth() {
        return connectionOptions.isHttpProxyAuthEnabled();
    }

    @Override
    public void setUseProxyChainAuth(boolean useProxyChainAuth) {
        connectionOptions.setHttpProxyAuthEnabled(useProxyChainAuth);
    }

    @Override
    public boolean isUseSocksProxy() {
        return connectionOptions.isSocksProxyEnabled();
    }

    @Override
    public void setUseSocksProxy(boolean useSocksProxy) {
        connectionOptions.setSocksProxyEnabled(useSocksProxy);
    }

    @Override
    public boolean isUseProxy(String hostName) {
        return connectionOptions.isUseHttpProxy(hostName);
    }

    @Override
    @ZapApiIgnore
    public boolean shouldResolveRemoteHostname(String hostname) {
        return connectionOptions.shouldResolveRemoteHostname(hostname);
    }

    @Override
    @ZapApiIgnore
    public List<DomainMatcher> getProxyExcludedDomains() {
        return connectionOptions.getHttpProxyExclusions().stream()
                .map(LegacyConnectionParam::exclusionToDomainMatcher)
                .collect(Collectors.toList());
    }

    @Override
    public void setProxyExcludedDomains(List<DomainMatcher> domains) {
        connectionOptions.setHttpProxyExclusions(
                domains.stream()
                        .map(LegacyConnectionParam::domainMatcherToExclusion)
                        .collect(Collectors.toList()));
    }

    private static DomainMatcher exclusionToDomainMatcher(HttpProxyExclusion exclusion) {
        DomainMatcher domainMatcher = new DomainMatcher(exclusion.getHost());
        domainMatcher.setEnabled(exclusion.isEnabled());
        return domainMatcher;
    }

    private static HttpProxyExclusion domainMatcherToExclusion(DomainMatcher matcher) {
        String host = matcher.isRegex() ? matcher.getValue() : Pattern.quote(matcher.getValue());
        Pattern pattern = HttpProxyExclusion.createHostPattern(host);
        return new HttpProxyExclusion(pattern, matcher.isEnabled());
    }
}
