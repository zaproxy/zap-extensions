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
package org.zaproxy.addon.network.internal.server.http;

import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.util.concurrent.EventExecutorGroup;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.handlers.PassThroughHandler;
import org.zaproxy.addon.network.internal.server.http.LocalServerHandler.SerialiseState;
import org.zaproxy.addon.network.internal.server.http.handlers.AliasApiRewriteHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.CloseOnRecursiveRequestHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.ConnectReceivedHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.DecodeResponseHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.HttpSenderHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.RemoveAcceptEncodingHandler;
import org.zaproxy.addon.network.internal.server.http.handlers.ZapApiHandler;

/** A local server/proxy, ones managed by the user. */
public class LocalServer extends HttpServer {

    private final LegacyProxyListenerHandler legacyHandler;
    private final PassThroughHandler passThroughHandler;
    private final HttpSenderHandler httpSenderHandler;

    private final LocalServerConfig serverConfig;

    private final SerialiseState serialiseState;
    private final Model model;

    private final AliasApiRewriteHandler aliasRewriteHandler;
    private final ZapApiHandler zapApiHandler;
    private final RemoveAcceptEncodingHandler removeAcceptEncodingHandler;
    private final DecodeResponseHandler decodeResponseHandler;

    /**
     * Constructs a {@code LocalServer} with the given properties.
     *
     * @param group the event loop group.
     * @param mainHandlerExecutor the event executor for the main handler.
     * @param sslCertificateService the certificate service.
     * @param legacyHandler the handler for legacy (core) listeners.
     * @param passThroughHandler the pass-through handler.
     * @param httpSenderHandler the HTTP Sender handler.
     * @param serverConfig the server configuration
     * @param serialiseState the serialisation state.
     * @param model the model to obtain the proxy excludes.
     */
    public LocalServer(
            NioEventLoopGroup group,
            EventExecutorGroup mainHandlerExecutor,
            SslCertificateService sslCertificateService,
            LegacyProxyListenerHandler legacyHandler,
            PassThroughHandler passThroughHandler,
            HttpSenderHandler httpSenderHandler,
            LocalServerConfig serverConfig,
            SerialiseState serialiseState,
            Model model) {
        super(group, mainHandlerExecutor, sslCertificateService);
        this.legacyHandler = legacyHandler;
        this.passThroughHandler = Objects.requireNonNull(passThroughHandler);
        this.httpSenderHandler = httpSenderHandler;
        this.serverConfig = Objects.requireNonNull(serverConfig);

        this.serialiseState = serialiseState;
        this.model = model;

        aliasRewriteHandler = new AliasApiRewriteHandler(serverConfig);
        zapApiHandler = new ZapApiHandler(serverConfig::isApiEnabled);
        removeAcceptEncodingHandler =
                new RemoveAcceptEncodingHandler(serverConfig::isRemoveAcceptEncoding);
        decodeResponseHandler = new DecodeResponseHandler(serverConfig::isDecodeResponse);

        setMainServerHandler(this::createLocalServerHandler);
    }

    private MainServerHandler createLocalServerHandler() {
        return new LocalServerHandler(
                legacyHandler,
                Arrays.asList(
                        ConnectReceivedHandler.getSetAndContinueInstance(),
                        aliasRewriteHandler,
                        zapApiHandler,
                        CloseOnRecursiveRequestHandler.getInstance(),
                        removeAcceptEncodingHandler,
                        decodeResponseHandler,
                        legacyHandler,
                        httpSenderHandler),
                serialiseState,
                model);
    }

    /**
     * Gets the configuration of the server.
     *
     * @return the configuration, never {@code null}.
     */
    public LocalServerConfig getConfig() {
        return serverConfig;
    }

    @Override
    protected void initChannel(SocketChannel ch) {
        super.initChannel(ch);

        ch.attr(ChannelAttributes.SERVER_CONFIG).set(serverConfig);
        ch.attr(ChannelAttributes.TLS_CONFIG).set(serverConfig.getTlsConfig());

        ch.pipeline().addBefore("http.connect", "pass-through", passThroughHandler);
    }

    /**
     * Starts the server using the configuration specified previously.
     *
     * @throws IOException if an error occurred while starting the server.
     */
    public void start() throws IOException {
        super.start(serverConfig.getAddress(), serverConfig.getPort());
    }

    /** @throws IOException always, the server should be started with {@link #start()}. */
    @Override
    public int start(String address, int port) throws IOException {
        throw new IOException("The local server should be started with the start() method.");
    }
}
