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
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.parosproxy.paros.network.ConnectionParam;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.codec.HttpRequestDecoder;
import org.zaproxy.addon.network.internal.codec.HttpResponseEncoder;
import org.zaproxy.addon.network.internal.handlers.ConnectRequestHandler;
import org.zaproxy.addon.network.internal.handlers.ReadTimeoutHandler;
import org.zaproxy.addon.network.internal.handlers.RecursiveRequestHandler;
import org.zaproxy.addon.network.internal.handlers.ServerExceptionHandler;
import org.zaproxy.addon.network.internal.handlers.TlsConfig;
import org.zaproxy.addon.network.internal.handlers.TlsProtocolHandler;
import org.zaproxy.addon.network.internal.server.BaseServer;

/**
 * A HTTP server.
 *
 * <p>Provides the following functionality:
 *
 * <ul>
 *   <li>Read timeout;
 *   <li>Handling of CONNECT requests and TLS upgrade;
 *   <li>Recursive check;
 *   <li>Exception handling;
 * </ul>
 */
public class HttpServer extends BaseServer {

    private static final TlsConfig DEFAULT_TLS_CONFIG = new TlsConfig();

    private final EventExecutorGroup mainHandlerExecutor;
    private final SslCertificateService sslCertificateService;
    private Supplier<MainServerHandler> handler;
    private DefaultServerConfig serverConfig;

    /**
     * Constructs a {@code HttpServer} with the given properties and no handler.
     *
     * <p>A handler must be set before starting the server.
     *
     * @param group the event loop group.
     * @param mainHandlerExecutor the event executor for the main handler.
     * @param sslCertificateService the certificate service.
     * @see #setMainServerHandler(Supplier)
     */
    protected HttpServer(
            NioEventLoopGroup group,
            EventExecutorGroup mainHandlerExecutor,
            SslCertificateService sslCertificateService) {
        super(group);
        this.mainHandlerExecutor = Objects.requireNonNull(mainHandlerExecutor);
        this.sslCertificateService = Objects.requireNonNull(sslCertificateService);

        this.serverConfig = new DefaultServerConfig();
        setChannelInitialiser(this::initChannel);
    }

    /**
     * Constructs a {@code HttpServer} with the given properties.
     *
     * @param group the event loop group.
     * @param mainHandlerExecutor the event executor for the main handler.
     * @param sslCertificateService the certificate service.
     * @param handler the main handler.
     */
    public HttpServer(
            NioEventLoopGroup group,
            EventExecutorGroup mainHandlerExecutor,
            SslCertificateService sslCertificateService,
            Supplier<MainServerHandler> handler) {
        this(group, mainHandlerExecutor, sslCertificateService);

        setMainServerHandler(handler);
    }

    /**
     * Sets the main server handler.
     *
     * @param handler the main server handler.
     * @throws NullPointerException if the given handler is {@code null}.
     */
    protected void setMainServerHandler(Supplier<MainServerHandler> handler) {
        this.handler = Objects.requireNonNull(handler);
    }

    protected void initChannel(SocketChannel ch) {
        ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).set(sslCertificateService);
        ch.attr(ChannelAttributes.SERVER_CONFIG).set(serverConfig);
        ch.attr(ChannelAttributes.TLS_CONFIG).set(DEFAULT_TLS_CONFIG);

        ch.pipeline()
                .addLast(
                        "timeout",
                        new ReadTimeoutHandler(ConnectionParam.DEFAULT_TIMEOUT, TimeUnit.SECONDS))
                .addLast("tls.upgrade", new TlsProtocolHandler())
                .addLast("http.decoder", new HttpRequestDecoder())
                .addLast("http.encoder", HttpResponseEncoder.getInstance())
                .addLast("http.connect", ConnectRequestHandler.getInstance())
                .addLast("http.recursive", RecursiveRequestHandler.getInstance())
                .addLast(mainHandlerExecutor, "http.main-handler", handler.get())
                .addLast("exception", new ServerExceptionHandler());
    }

    @Override
    public int start(String address, int port) throws IOException {
        if (handler == null) {
            throw new IOException("No main server handler set.");
        }
        int boundPort = super.start(address, port);
        serverConfig.setAddress(address);
        return boundPort;
    }
}
