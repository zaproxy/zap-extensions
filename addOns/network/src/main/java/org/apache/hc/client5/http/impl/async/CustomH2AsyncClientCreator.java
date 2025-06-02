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
package org.apache.hc.client5.http.impl.async;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.HttpRequestRetryStrategy;
import org.apache.hc.client5.http.async.AsyncExecChainHandler;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.CredentialsProvider;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.impl.ChainElement;
import org.apache.hc.client5.http.impl.CookieSpecSupport;
import org.apache.hc.client5.http.impl.DefaultAuthenticationStrategy;
import org.apache.hc.client5.http.impl.DefaultSchemePortResolver;
import org.apache.hc.client5.http.impl.nio.MultihomeConnectionInitiator;
import org.apache.hc.client5.http.routing.HttpRoutePlanner;
import org.apache.hc.core5.concurrent.DefaultThreadFactory;
import org.apache.hc.core5.function.Resolver;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.config.CharCodingConfig;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.NamedElementChain;
import org.apache.hc.core5.http.nio.command.ShutdownCommand;
import org.apache.hc.core5.http.nio.ssl.TlsStrategy;
import org.apache.hc.core5.http.protocol.DefaultHttpProcessor;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.apache.hc.core5.http2.config.H2Config;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.reactor.Command;
import org.apache.hc.core5.reactor.DefaultConnectingIOReactor;
import org.apache.hc.core5.reactor.IOEventHandlerFactory;
import org.apache.hc.core5.reactor.IOReactorConfig;

public class CustomH2AsyncClientCreator {

    private CustomH2AsyncClientCreator() {}

    public static CloseableHttpAsyncClient create(
            CharCodingConfig charCodingConfig,
            HttpRoutePlanner routePlanner,
            Lookup<AuthSchemeFactory> authSchemeRegistry,
            CredentialsProvider credentialsProvider,
            RequestConfig defaultRequestConfig,
            HttpProcessor proxyHttpProcessor,
            HttpProcessor httpProcessor,
            HttpRequestRetryStrategy requestRetryStrategy,
            Resolver<HttpHost, ConnectionConfig> connectionConfigResolver,
            TlsStrategy tlsStrategy) {

        boolean authCachingDisabled = false;

        NamedElementChain<AsyncExecChainHandler> execChainDefinition = new NamedElementChain<>();

        execChainDefinition.addLast(
                new H2AsyncMainClientExec(httpProcessor), ChainElement.MAIN_TRANSPORT.name());

        execChainDefinition.addFirst(
                new AsyncConnectExec(
                        proxyHttpProcessor,
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultSchemePortResolver.INSTANCE,
                        authCachingDisabled),
                ChainElement.CONNECT.name());

        execChainDefinition.addFirst(
                new ZapAsyncProtocolExec(
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultAuthenticationStrategy.INSTANCE,
                        DefaultSchemePortResolver.INSTANCE,
                        authCachingDisabled),
                ChainElement.PROTOCOL.name());

        execChainDefinition.addFirst(
                new AsyncHttpRequestRetryExec(requestRetryStrategy), ChainElement.RETRY.name());

        AsyncPushConsumerRegistry pushConsumerRegistry = new AsyncPushConsumerRegistry();
        IOEventHandlerFactory ioEventHandlerFactory =
                new H2AsyncClientProtocolStarter(
                        new DefaultHttpProcessor((HttpRequestInterceptor[]) null, null),
                        (request, context) -> pushConsumerRegistry.get(request),
                        H2Config.DEFAULT,
                        charCodingConfig);

        DefaultConnectingIOReactor ioReactor =
                new DefaultConnectingIOReactor(
                        ioEventHandlerFactory,
                        IOReactorConfig.custom()
                                .setIoThreadCount(
                                        IOReactorConfig.Builder.getDefaultMaxIOThreadCount())
                                .build(),
                        new DefaultThreadFactory("ZAP-h2c-dispatch", true),
                        LoggingIOSessionDecorator.INSTANCE,
                        LoggingExceptionCallback.INSTANCE,
                        null,
                        ioSession ->
                                ioSession.enqueue(
                                        new ShutdownCommand(CloseMode.GRACEFUL),
                                        Command.Priority.IMMEDIATE));

        NamedElementChain<AsyncExecChainHandler>.Node current = execChainDefinition.getLast();
        AsyncExecChainElement execChain = null;
        while (current != null) {
            execChain = new AsyncExecChainElement(current.getValue(), execChain);
            current = current.getPrevious();
        }

        MultihomeConnectionInitiator connectionInitiator =
                new MultihomeConnectionInitiator(ioReactor, null);
        InternalH2ConnPool connPool =
                new InternalH2ConnPool(connectionInitiator, host -> null, tlsStrategy);
        connPool.setConnectionConfigResolver(connectionConfigResolver);

        List<Closeable> closeablesCopy = new ArrayList<>(1);
        closeablesCopy.add(connPool);

        return new InternalH2AsyncClient(
                ioReactor,
                execChain,
                pushConsumerRegistry,
                new DefaultThreadFactory("ZAP-h2c", true),
                connPool,
                routePlanner,
                CookieSpecSupport.createDefault(),
                authSchemeRegistry,
                new BasicCookieStore(),
                credentialsProvider,
                defaultRequestConfig,
                closeablesCopy);
    }
}
