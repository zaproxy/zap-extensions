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
package org.apache.hc.client5.http.impl.classic;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.classic.ExecChainHandler;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.ChainElement;
import org.apache.hc.client5.http.impl.CookieSpecSupport;
import org.apache.hc.client5.http.impl.DefaultAuthenticationStrategy;
import org.apache.hc.client5.http.impl.DefaultClientConnectionReuseStrategy;
import org.apache.hc.client5.http.impl.DefaultConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.impl.DefaultSchemePortResolver;
import org.apache.hc.client5.http.impl.DefaultUserTokenHandler;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.core5.http.ConnectionReuseStrategy;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.NamedElementChain;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.zaproxy.addon.network.internal.client.apachev5.ZapHttpRequestExecutor;

public final class CustomHttpClientCreator {

    private CustomHttpClientCreator() {}

    public static CloseableHttpClient create(
            HttpClientConnectionManager connectionManager,
            HttpRoutePlanner routePlanner,
            Lookup<AuthSchemeFactory> authSchemeRegistry,
            CredentialsProvider credentialsProvider,
            RequestConfig defaultRequestConfig,
            HttpProcessor proxyHttpProcessor,
            HttpProcessor httpProcessor,
            HttpRequestRetryStrategy requestRetryStrategy) {

        boolean authCachingDisabled = false;
        ConnectionReuseStrategy reuseStrategy = DefaultClientConnectionReuseStrategy.INSTANCE;

        NamedElementChain<ExecChainHandler> execChainDefinition = new NamedElementChain<>();

        execChainDefinition.addLast(
                new MainClientExec(
                        connectionManager,
                        httpProcessor,
                        reuseStrategy,
                        DefaultConnectionKeepAliveStrategy.INSTANCE,
                        DefaultUserTokenHandler.INSTANCE),
                ChainElement.MAIN_TRANSPORT.name());

        execChainDefinition.addFirst(
                new ConnectExec(
                        reuseStrategy,
                        proxyHttpProcessor,
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultSchemePortResolver.INSTANCE,
                        authCachingDisabled),
                ChainElement.CONNECT.name());

        execChainDefinition.addFirst(
                new ProtocolExec(
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultSchemePortResolver.INSTANCE,
                        authCachingDisabled),
                ChainElement.PROTOCOL.name());

        execChainDefinition.addFirst(
                new ZapHttpRequestRetryExec(requestRetryStrategy), ChainElement.RETRY.name());

        NamedElementChain<ExecChainHandler>.Node current = execChainDefinition.getLast();
        ExecChainElement execChain = null;
        while (current != null) {
            execChain = new ExecChainElement(current.getValue(), execChain);
            current = current.getPrevious();
        }

        List<Closeable> closeables = new ArrayList<>(1);
        if (connectionManager instanceof PoolingHttpClientConnectionManager) {
            closeables.add(connectionManager);
        }

        return new ZapInternalHttpClient(
                connectionManager,
                new ZapHttpRequestExecutor(),
                execChain,
                routePlanner,
                CookieSpecSupport.createDefault(),
                authSchemeRegistry,
                new BasicCookieStore(),
                credentialsProvider,
                defaultRequestConfig,
                closeables);
    }
}
