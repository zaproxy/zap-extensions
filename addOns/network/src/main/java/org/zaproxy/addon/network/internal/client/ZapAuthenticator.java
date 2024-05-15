/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.common.HttpProxy;

/**
 * ZAP's {@link Authenticator}.
 *
 * <p>Authenticates to HTTP and SOCKS proxies.
 */
public class ZapAuthenticator extends Authenticator {

    private static final ZapAuthenticator SINGLETON = new ZapAuthenticator();

    private static final Logger LOGGER = LogManager.getLogger(ZapAuthenticator.class);

    private static ConnectionOptions connectionOptions;

    private ZapAuthenticator() {}

    /**
     * Gets the singleton.
     *
     * @return the ZAP's {@code Authenticator}.
     */
    public static ZapAuthenticator getSingleton() {
        return SINGLETON;
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        PasswordAuthentication passwordAuthentication = getPasswordAuthenticationImpl();
        if (LOGGER.isDebugEnabled()) {
            StringBuilder strBuilder = new StringBuilder();
            strBuilder.append("Getting password authentication for:").append('\n');
            strBuilder.append("Host      = ").append(getRequestingHost()).append('\n');
            strBuilder.append("Site      = ").append(getRequestingSite()).append('\n');
            strBuilder.append("Port      = ").append(getRequestingPort()).append('\n');
            strBuilder.append("Protocol  = ").append(getRequestingProtocol()).append('\n');
            strBuilder.append("Prompt    = ").append(getRequestingPrompt()).append('\n');
            strBuilder.append("Scheme    = ").append(getRequestingScheme()).append('\n');
            strBuilder.append("URL       = ").append(getRequestingURL()).append('\n');
            strBuilder.append("Auth Type = ").append(getRequestorType()).append('\n');
            strBuilder.append("Result: ");
            if (passwordAuthentication == null) {
                strBuilder.append(passwordAuthentication);
            } else {
                strBuilder.append("[Username: ").append(passwordAuthentication.getUserName());
                strBuilder.append(", Password: *****]");
            }
            LOGGER.debug(strBuilder.toString());
        }
        return passwordAuthentication;
    }

    private PasswordAuthentication getPasswordAuthenticationImpl() {
        if (isForSocksProxy()) {
            return getConnectionOptions().getSocksProxy().getPasswordAuthentication();
        }

        if (isForHttpProxy()) {
            return getConnectionOptions().getHttpProxy().getPasswordAuthentication();
        }

        return null;
    }

    /**
     * Tells whether or not the password authentication is being requested for the SOCKS proxy.
     *
     * @return {@code true} if the request is for the SOCKS proxy, {@code false} otherwise.
     */
    private boolean isForSocksProxy() {
        if (!getConnectionOptions().isSocksProxyEnabled()) {
            return false;
        }

        SocksProxy socksProxy = getConnectionOptions().getSocksProxy();
        return socksProxy.getVersion() == SocksProxy.Version.SOCKS5
                && getRequestorType() == RequestorType.SERVER
                && SocksProxy.Version.SOCKS5.name().equals(getRequestingProtocol())
                && socksProxy.getPort() == getRequestingPort()
                && socksProxy.getHost().equals(getRequestingHost());
    }

    /**
     * Tells whether or not the password authentication is being requested for the outgoing HTTP
     * proxy.
     *
     * @return {@code true} if the request is for the outgoing HTTP proxy, {@code false} otherwise.
     */
    private boolean isForHttpProxy() {
        if (!getConnectionOptions().isHttpProxyEnabled()) {
            return false;
        }

        HttpProxy httpProxy = getConnectionOptions().getHttpProxy();
        return getRequestorType() == RequestorType.PROXY
                && getRequestingURL() != null
                && getConnectionOptions().isUseHttpProxy(getRequestingURL().getHost())
                && httpProxy.getPort() == getRequestingPort()
                && httpProxy.getHost().equals(getRequestingHost());
    }

    private static ConnectionOptions getConnectionOptions() {
        if (connectionOptions == null) {
            connectionOptions =
                    Model.getSingleton().getOptionsParam().getParamSet(ConnectionOptions.class);
        }
        return connectionOptions;
    }
}
