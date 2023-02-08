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
package org.zaproxy.addon.network.internal.handlers;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import java.util.List;
import javax.net.ssl.SSLException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.TlsUtils;
import org.zaproxy.addon.network.internal.cert.SniX509KeyManager;

/**
 * Handles SSL/TLS connections as a server, with ALPN if enabled.
 *
 * <p>The handler removes itself after handling the possible SSL/TLS connection.
 *
 * @see TlsConfig
 * @see ChannelAttributes#TLS_CONFIG
 */
public class TlsProtocolHandler extends ByteToMessageDecoder {

    /** The name of the handler added to handle the SSL/TLS connection. */
    public static final String TLS_HANDLER_NAME = "tls";

    private static final String HTTP2_PREFACE_HANDLER = "http2.preface";

    private static final int SSL_RECORD_HEADER_LENGTH = 5;

    private final String authority;

    /** Constructs a {@code TlsProtocolHandler} with no authority. */
    public TlsProtocolHandler() {
        this(null);
    }

    /**
     * Constructs a {@code TlsProtocolHandler} with the given authority.
     *
     * <p>The authority is used as fallback if not able to obtain the domain during the handshake.
     *
     * @param authority the authority that the connection is being established to.
     */
    public TlsProtocolHandler(String authority) {
        this.authority = authority;
    }

    /**
     * Gets the authority that was provided when creating this {@code TlsProtocolHandler}.
     *
     * @return the authority, might be {@code null}.
     */
    String getAuthority() {
        return authority;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        ctx.pipeline().addAfter(ctx.name(), HTTP2_PREFACE_HANDLER, new Http2PrefaceHandler());
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out)
            throws Exception {
        if (in.readableBytes() < SSL_RECORD_HEADER_LENGTH) {
            return;
        }

        boolean upgraded = upgrade(ctx, in);
        ctx.channel().attr(ChannelAttributes.TLS_UPGRADED).set(upgraded);
        ctx.pipeline().remove(this);
    }

    private boolean upgrade(ChannelHandlerContext ctx, ByteBuf in) throws Exception {
        if (!SslHandler.isEncrypted(in)) {
            return false;
        }

        Channel ch = ctx.channel();
        TlsConfig config = ch.attr(ChannelAttributes.TLS_CONFIG).get();

        SslContext sslCtx =
                SslContextBuilder.forServer(
                                new SniX509KeyManager(
                                        ch.attr(ChannelAttributes.CERTIFICATE_SERVICE).get(),
                                        ch.attr(ChannelAttributes.LOCAL_ADDRESS).get().getAddress(),
                                        authority))
                        .protocols(config.getTlsProtocols())
                        .applicationProtocolConfig(createApplicationProtocolConfig(config))
                        .build();
        ctx.pipeline().addAfter(ctx.name(), TLS_HANDLER_NAME, sslCtx.newHandler(ctx.alloc()));
        if (config.isAlpnEnabled()) {
            ctx.pipeline().addAfter(TLS_HANDLER_NAME, "tls.alpn", new AlpnHandlerImpl());
        }

        return true;
    }

    private static ApplicationProtocolConfig createApplicationProtocolConfig(TlsConfig config) {
        if (!config.isAlpnEnabled()) {
            return null;
        }

        return new ApplicationProtocolConfig(
                Protocol.ALPN,
                SelectorFailureBehavior.FATAL_ALERT,
                SelectedListenerFailureBehavior.FATAL_ALERT,
                config.getApplicationProtocols());
    }

    private static class AlpnHandlerImpl extends ApplicationProtocolNegotiationHandler {

        private static final Logger LOGGER = LogManager.getLogger(AlpnHandlerImpl.class);

        private static final String NO_PROTOCOL_NEGOTIATED = "zap.no-protocol";

        protected AlpnHandlerImpl() {
            super(NO_PROTOCOL_NEGOTIATED);
        }

        @Override
        protected void configurePipeline(ChannelHandlerContext ctx, String negotiatedProtocol)
                throws Exception {
            String protocol = negotiatedProtocol;
            if (NO_PROTOCOL_NEGOTIATED.equals(protocol)) {
                protocol = TlsUtils.APPLICATION_PROTOCOL_HTTP_1_1;
                LOGGER.debug("Using fallback protocol: {}", protocol);
            } else {
                LOGGER.debug("Negotiated protocol: {}", protocol);
            }

            ctx.pipeline().remove(HTTP2_PREFACE_HANDLER);

            PipelineConfigurator configurator =
                    ctx.channel().attr(ChannelAttributes.PIPELINE_CONFIGURATOR).get();
            if (configurator != null) {
                configurator.configure(ctx, protocol);
            }
        }

        @Override
        protected void handshakeFailure(ChannelHandlerContext ctx, Throwable cause)
                throws Exception {
            ctx.fireExceptionCaught(cause);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if (cause instanceof DecoderException && (cause.getCause() instanceof SSLException)) {
                super.exceptionCaught(ctx, cause);
                return;
            }

            ctx.fireExceptionCaught(cause);
        }
    }
}
